package main

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"
)

// telemetry is a periodic host health snapshot reported to the gateway.
type telemetry struct {
	Hostname    string  `json:"hostname"`
	OS          string  `json:"os"`
	Kernel      string  `json:"kernel,omitempty"`
	UptimeSec   float64 `json:"uptime_sec"`
	Load1       float64 `json:"load1"`
	Load5       float64 `json:"load5"`
	Load15      float64 `json:"load15"`
	MemTotalMB  uint64  `json:"mem_total_mb"`
	MemAvailMB  uint64  `json:"mem_avail_mb"`
	DiskTotalGB float64 `json:"disk_total_gb"`
	DiskFreeGB  float64 `json:"disk_free_gb"`
	CPUPct      float64 `json:"cpu_pct"`
	NetRxKBs    float64 `json:"net_rx_kbs"`
	NetTxKBs    float64 `json:"net_tx_kbs"`
	TS          string  `json:"ts"`
}

// Previous samples for delta-based CPU% and network rates.
var (
	prevCPUBusy, prevCPUTotal uint64
	prevNetRx, prevNetTx      uint64
	prevSampleAt              time.Time
)

const telemetryTick = 30 * time.Second

// runTelemetry collects and reports a host snapshot every telemetryTick.
func runTelemetry(send func([]byte)) {
	emit := func() {
		t := collect()
		if b, err := json.Marshal(t); err == nil {
			send(b)
		}
	}
	emit() // report immediately on connect
	ticker := time.NewTicker(telemetryTick)
	defer ticker.Stop()
	for range ticker.C {
		emit()
	}
}

func collect() telemetry {
	t := telemetry{TS: time.Now().UTC().Format(time.RFC3339)}
	t.Hostname, _ = os.Hostname()
	t.OS = prettyOS()
	readUptime(&t)
	readLoad(&t)
	readMem(&t)
	readCPU(&t)
	readNet(&t)
	collectPlatform(&t) // disk + kernel (OS-specific)
	return t
}

// readCPU computes CPU utilization % from /proc/stat deltas between samples.
func readCPU(t *telemetry) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		f := strings.Fields(line)[1:]
		var total, idle uint64
		for i, v := range f {
			n, _ := strconv.ParseUint(v, 10, 64)
			total += n
			if i == 3 || i == 4 { // idle + iowait
				idle += n
			}
		}
		busy := total - idle
		if prevCPUTotal > 0 && total > prevCPUTotal {
			dt := total - prevCPUTotal
			db := busy - prevCPUBusy
			t.CPUPct = round1(float64(db) / float64(dt) * 100)
		}
		prevCPUBusy, prevCPUTotal = busy, total
		break
	}
}

// readNet computes aggregate rx/tx KB/s from /proc/net/dev deltas (excludes lo).
func readNet(t *telemetry) {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return
	}
	var rx, tx uint64
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		if iface == "lo" || iface == "" {
			continue
		}
		f := strings.Fields(parts[1])
		if len(f) < 9 {
			continue
		}
		r, _ := strconv.ParseUint(f[0], 10, 64)
		x, _ := strconv.ParseUint(f[8], 10, 64)
		rx += r
		tx += x
	}
	now := time.Now()
	if !prevSampleAt.IsZero() {
		secs := now.Sub(prevSampleAt).Seconds()
		if secs > 0 && rx >= prevNetRx && tx >= prevNetTx {
			t.NetRxKBs = round1(float64(rx-prevNetRx) / 1024 / secs)
			t.NetTxKBs = round1(float64(tx-prevNetTx) / 1024 / secs)
		}
	}
	prevNetRx, prevNetTx, prevSampleAt = rx, tx, now
}

func prettyOS() string {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	return ""
}

func readUptime(t *telemetry) {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return
	}
	if f := strings.Fields(string(b)); len(f) > 0 {
		t.UptimeSec, _ = strconv.ParseFloat(f[0], 64)
	}
}

func readLoad(t *telemetry) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return
	}
	f := strings.Fields(string(b))
	if len(f) >= 3 {
		t.Load1, _ = strconv.ParseFloat(f[0], 64)
		t.Load5, _ = strconv.ParseFloat(f[1], 64)
		t.Load15, _ = strconv.ParseFloat(f[2], 64)
	}
}

func readMem(t *telemetry) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		kb, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			t.MemTotalMB = kb / 1024
		case "MemAvailable:":
			t.MemAvailMB = kb / 1024
		}
	}
}

func round1(f float64) float64 {
	return float64(int64(f*10+0.5)) / 10
}
