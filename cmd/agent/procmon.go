package main

import (
	"encoding/json"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// execEvent describes a process execution observed on the host.
type execEvent struct {
	Type    string `json:"type"`
	Source  string `json:"source"` // "connector" (kernel, real-time) or "poll" (/proc scan)
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	UID     int    `json:"uid"`
	User    string `json:"user,omitempty"`
	Comm    string `json:"comm,omitempty"`
	Cmdline string `json:"cmdline"`
	TS      string `json:"ts"`
}

// uidNameCache memoizes uid -> username lookups (single monitor goroutine).
var uidNameCache = map[int]string{}

func lookupUser(uid int) string {
	if uid < 0 {
		return ""
	}
	if n, ok := uidNameCache[uid]; ok {
		return n
	}
	n := ""
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		n = u.Username
	}
	uidNameCache[uid] = n
	return n
}

// monitorProcesses is the host command logging entry point. Selection:
//
//	HOST_MONITOR=connector  -> kernel netlink proc connector only (real-time)
//	HOST_MONITOR=poll       -> /proc polling only
//	HOST_MONITOR=auto|unset -> try the connector, fall back to polling
//
// The connector captures EVERY exec syscall in real time with no polling gap —
// the leak-free path for real host deployments. It requires CAP_NET_ADMIN and
// the host network+pid namespaces (the agent runs as root via systemd, so this
// holds). Polling is the dependency-free fallback.
func monitorProcesses(send func([]byte)) {
	const procDir = "/proc"
	if _, err := os.Stat(procDir); err != nil {
		log.Printf("host command logging unavailable (no %s on this OS)", procDir)
		return
	}

	mode := os.Getenv("HOST_MONITOR")
	if mode == "" {
		mode = "auto"
	}

	switch mode {
	case "poll":
		log.Println("host command logging active (/proc poll, forced)")
		monitorProcPoll(send)
	case "connector":
		log.Println("host command logging active (kernel proc connector, forced)")
		if err := monitorExecConnector(send); err != nil {
			log.Printf("connector failed: %v", err)
		}
	default: // auto
		if err := monitorExecConnector(send); err != nil {
			log.Printf("kernel proc connector unavailable (%v); falling back to /proc poll", err)
			monitorProcPoll(send)
		}
	}
}

// pollInterval controls how often /proc is scanned in poll mode.
const pollInterval = 300 * time.Millisecond

// monitorProcPoll scans /proc for new pids and reports each as an exec event.
// Best-effort: sub-interval (very short-lived) processes can be missed. The
// kernel connector has no such gap.
func monitorProcPoll(send func([]byte)) {
	const procDir = "/proc"
	seen := map[int]bool{}
	first := true
	for {
		current := map[int]bool{}
		entries, _ := os.ReadDir(procDir)
		for _, e := range entries {
			pid, err := strconv.Atoi(e.Name())
			if err != nil {
				continue
			}
			current[pid] = true
			if seen[pid] {
				continue
			}
			seen[pid] = true
			if first {
				continue // prime: skip already-running processes
			}
			ev := buildExecEvent(pid)
			if ev == nil || ev.Cmdline == "" {
				continue // unreadable or kernel thread
			}
			ev.Source = "poll"
			if b, err := json.Marshal(ev); err == nil {
				send(b)
			}
		}
		for pid := range seen {
			if !current[pid] {
				delete(seen, pid)
			}
		}
		first = false
		time.Sleep(pollInterval)
	}
}

// buildExecEvent reads cmdline/comm/status for a pid and builds an execEvent.
// Returns nil if the process is already gone or unreadable.
func buildExecEvent(pid int) *execEvent {
	base := filepath.Join("/proc", strconv.Itoa(pid))

	raw, err := os.ReadFile(filepath.Join(base, "cmdline"))
	if err != nil {
		return nil
	}
	cmdline := strings.TrimSpace(strings.ReplaceAll(string(raw), "\x00", " "))

	comm := ""
	if b, err := os.ReadFile(filepath.Join(base, "comm")); err == nil {
		comm = strings.TrimSpace(string(b))
	}

	uid, ppid := -1, -1
	if b, err := os.ReadFile(filepath.Join(base, "status")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			switch {
			case strings.HasPrefix(line, "PPid:"):
				ppid, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
			case strings.HasPrefix(line, "Uid:"):
				if fields := strings.Fields(strings.TrimPrefix(line, "Uid:")); len(fields) > 0 {
					uid, _ = strconv.Atoi(fields[0])
				}
			}
		}
	}

	return &execEvent{
		Type:    "exec",
		PID:     pid,
		PPID:    ppid,
		UID:     uid,
		User:    lookupUser(uid),
		Comm:    comm,
		Cmdline: cmdline,
		TS:      time.Now().UTC().Format(time.RFC3339),
	}
}
