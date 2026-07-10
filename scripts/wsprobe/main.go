// wsprobe is a tiny WebSocket test client used by scripts/e2e_test.sh to
// exercise the gateway's WS endpoints (ssh sessions, shadowing, port-forward).
//
//	go run ./scripts/wsprobe ssh     <base> <id> <token> <reason> <cmd> <secs>
//	go run ./scripts/wsprobe watch   <base> <sessionId> <token> <secs>
//	go run ./scripts/wsprobe forward <base> <id> <token> <host> <port> <secs>
//
// It prints everything it receives to stdout; the harness greps for markers.
package main

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/websocket"

	"github.com/shellwarden/shellwarden/internal/auth"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: wsprobe <ssh|watch|forward|totp> ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "ssh":
		runSSH(os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6], atoi(os.Args[7]))
	case "watch":
		runRead(os.Args[2], "/ws/watch/"+os.Args[3], os.Args[4], nil, atoi(os.Args[5]))
	case "forward":
		runForward(os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6], atoi(os.Args[7]))
	case "resume":
		runResume(os.Args[2], os.Args[3], os.Args[4])
	case "totp":
		code, err := auth.TOTPCode(os.Args[2], time.Now())
		if err != nil {
			os.Exit(1)
		}
		fmt.Print(code)
	default:
		os.Exit(2)
	}
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

func dial(base, path, token string, q url.Values) (*websocket.Conn, error) {
	u, _ := url.Parse(base)
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	u.Path = path
	if q == nil {
		q = url.Values{}
	}
	q.Set("token", token)
	u.RawQuery = q.Encode()
	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	return c, err
}

func runSSH(base, id, token, reason, cmd string, secs int) {
	q := url.Values{}
	if reason != "" {
		q.Set("reason", reason)
	}
	c, err := dial(base, "/ws/ssh/"+id, token, q)
	if err != nil {
		fmt.Println("DIAL_ERR", err)
		os.Exit(1)
	}
	defer c.Close()
	go func() {
		time.Sleep(800 * time.Millisecond)
		c.WriteMessage(websocket.TextMessage, []byte(cmd+"\n"))
	}()
	readUntil(c, secs)
}

func runForward(base, id, token, host, port string, secs int) {
	q := url.Values{}
	q.Set("host", host)
	q.Set("port", port)
	c, err := dial(base, "/ws/forward/"+id, token, q)
	if err != nil {
		fmt.Println("DIAL_ERR", err)
		os.Exit(1)
	}
	defer c.Close()
	readUntil(c, secs)
}

func runRead(base, path, token string, q url.Values, secs int) {
	c, err := dial(base, path, token, q)
	if err != nil {
		fmt.Println("DIAL_ERR", err)
		os.Exit(1)
	}
	defer c.Close()
	readUntil(c, secs)
}

// runResume sets a shell variable, drops the WS, reconnects with ?resume=, and
// reads $RESUME_STATE back — proving the shell survived the disconnect.
func runResume(base, id, token string) {
	c1, err := dial(base, "/ws/ssh/"+id, token, nil)
	if err != nil {
		fmt.Println("DIAL_ERR", err)
		os.Exit(1)
	}
	sessID := ""
	go func() {
		time.Sleep(900 * time.Millisecond)
		c1.WriteMessage(websocket.TextMessage, []byte("RESUME_STATE=hello42\n"))
	}()
	c1.SetReadDeadline(time.Now().Add(2500 * time.Millisecond))
	for {
		mt, msg, err := c1.ReadMessage()
		if err != nil {
			break
		}
		if mt == websocket.TextMessage {
			if i := indexOf(string(msg), `"id":"`); i >= 0 {
				rest := string(msg)[i+6:]
				if j := indexOf(rest, `"`); j >= 0 {
					sessID = rest[:j]
				}
			}
		}
	}
	c1.Close() // drop the "browser" — server keeps the shell alive
	if sessID == "" {
		fmt.Println("NO_SESSION_ID")
		os.Exit(1)
	}
	time.Sleep(600 * time.Millisecond)

	q := url.Values{}
	q.Set("resume", sessID)
	c2, err := dial(base, "/ws/ssh/"+id, token, q)
	if err != nil {
		fmt.Println("RESUME_DIAL_ERR", err)
		os.Exit(1)
	}
	defer c2.Close()
	go func() {
		time.Sleep(700 * time.Millisecond)
		c2.WriteMessage(websocket.TextMessage, []byte("echo GOT:$RESUME_STATE\n"))
	}()
	readUntil(c2, 3)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func readUntil(c *websocket.Conn, secs int) {
	c.SetReadDeadline(time.Now().Add(time.Duration(secs) * time.Second))
	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			return
		}
		os.Stdout.Write(msg)
	}
}
