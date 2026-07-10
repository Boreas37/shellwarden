package main

import (
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"

	"github.com/shellwarden/shellwarden/internal/agent"
)

const (
	configPath    = "/etc/shellwarden/agent.conf"
	localSSHD     = "127.0.0.1:22"
	heartbeatTick = 30 * time.Second
	reconnectWait = 5 * time.Second
)

func main() {
	// Load config file if present; env vars still take precedence afterwards.
	_ = godotenv.Load(configPath)

	gatewayURL := os.Getenv("GATEWAY_URL")
	token := os.Getenv("AGENT_TOKEN")
	serverID := os.Getenv("SERVER_ID")

	if gatewayURL == "" || token == "" {
		log.Fatal("GATEWAY_URL and AGENT_TOKEN are required")
	}
	log.Printf("shellwarden-agent starting (server %s -> %s)", serverID, gatewayURL)

	// Host command logging: monitor runs once for the agent's lifetime and
	// enqueues exec events; the current tunnel connection drains the queue.
	go monitorProcesses(func(b []byte) {
		select {
		case execEvents <- b:
		default: // queue full (gateway offline) — drop
		}
	})

	// Host telemetry: periodic health snapshots.
	go runTelemetry(func(b []byte) {
		select {
		case telemetryEvents <- b:
		default:
		}
	})

	// Vulnerability scanning: periodic distro-native CVE/update checks.
	go runVulnScan(func(b []byte) {
		select {
		case scanEvents <- b:
		default:
		}
	})

	// Reconnect loop: agents must survive gateway restarts.
	for {
		if err := connectAndServe(gatewayURL, token, serverID); err != nil {
			log.Printf("tunnel closed: %v; reconnecting in %s", err, reconnectWait)
		}
		time.Sleep(reconnectWait)
	}
}

// execEvents/telemetryEvents buffer agent-originated frames between collectors
// and whichever tunnel connection is currently active.
var execEvents = make(chan []byte, 1024)
var telemetryEvents = make(chan []byte, 16)
var scanEvents = make(chan []byte, 4)

// connectAndServe opens one WebSocket to the gateway and serves bridged
// sessions until the connection drops.
func connectAndServe(gatewayURL, token, serverID string) error {
	endpoint := gatewayURL + "/agent/connect"
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)

	ws, _, err := websocket.DefaultDialer.Dial(endpoint, header)
	if err != nil {
		return err
	}
	log.Println("connected to gateway")

	ac := agent.NewAgentConn(serverID, ws)

	// Heartbeat pinger.
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(heartbeatTick)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if err := ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second)); err != nil {
					return
				}
			}
		}
	}()
	defer close(stop)

	// Forward buffered exec events + telemetry to the gateway while connected.
	go func() {
		for {
			select {
			case <-stop:
				return
			case b := <-execEvents:
				if err := ac.SendLog(b); err != nil {
					return
				}
			case b := <-telemetryEvents:
				if err := ac.SendTelemetry(b); err != nil {
					return
				}
			case b := <-scanEvents:
				if err := ac.SendScan(b); err != nil {
					return
				}
			}
		}
	}()

	// For each Open frame from the gateway, dial local sshd and bridge.
	return ac.ReadLoop(func(id uuid.UUID, conn net.Conn) {
		go bridge(conn)
	})
}

// bridge connects a multiplexed stream to the local sshd and copies bytes in
// both directions until either side closes.
func bridge(stream net.Conn) {
	defer stream.Close()

	local, err := net.DialTimeout("tcp", localSSHD, 10*time.Second)
	if err != nil {
		log.Printf("dial local sshd failed: %v", err)
		return
	}
	defer local.Close()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(local, stream); done <- struct{}{} }()
	go func() { _, _ = io.Copy(stream, local); done <- struct{}{} }()
	<-done
}
