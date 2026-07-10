package bulk

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/shellwarden/shellwarden/internal/agent"
	"github.com/shellwarden/shellwarden/internal/crypto"
	"github.com/shellwarden/shellwarden/internal/models"
)

// maxConcurrency caps simultaneous host connections (CLAUDE.md: 50).
const maxConcurrency = 50

// Executor fans a command out across all servers in a group.
type Executor struct {
	DB       *sql.DB
	Registry *agent.Registry
	Cipher   *crypto.Cipher
	Timeout  time.Duration

	mu          sync.Mutex
	subscribers map[string][]chan models.BulkResult // job_id -> result listeners
}

// NewExecutor builds an executor with the given per-host timeout (seconds).
func NewExecutor(db *sql.DB, reg *agent.Registry, cipher *crypto.Cipher, timeoutSec int) *Executor {
	if timeoutSec <= 0 {
		timeoutSec = 30
	}
	return &Executor{
		DB:          db,
		Registry:    reg,
		Cipher:      cipher,
		Timeout:     time.Duration(timeoutSec) * time.Second,
		subscribers: make(map[string][]chan models.BulkResult),
	}
}

// Subscribe registers a channel to receive results for a job as hosts complete.
// The returned cancel func unsubscribes.
func (e *Executor) Subscribe(jobID string) (<-chan models.BulkResult, func()) {
	ch := make(chan models.BulkResult, 64)
	e.mu.Lock()
	e.subscribers[jobID] = append(e.subscribers[jobID], ch)
	e.mu.Unlock()

	cancel := func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		subs := e.subscribers[jobID]
		for i, c := range subs {
			if c == ch {
				e.subscribers[jobID] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
	}
	return ch, cancel
}

func (e *Executor) publish(jobID string, res models.BulkResult) {
	e.mu.Lock()
	subs := append([]chan models.BulkResult(nil), e.subscribers[jobID]...)
	e.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- res:
		default: // slow consumer — drop rather than block the executor
		}
	}
}

// Run executes the job's command (or script) across the group concurrently. It
// blocks until all hosts finish, then marks the job complete. Run in a goroutine.
func (e *Executor) Run(jobID, groupID, command string, script bool) {
	servers, err := e.resolveServers(groupID)
	if err != nil {
		log.Printf("bulk %s: resolve servers failed: %v", jobID, err)
		e.finish(jobID)
		return
	}

	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	for _, srv := range servers {
		wg.Add(1)
		sem <- struct{}{}
		go func(s models.Server) {
			defer wg.Done()
			defer func() { <-sem }()
			res := e.runOne(jobID, s, command, script)
			e.store(res)
			e.publish(jobID, res)
		}(srv)
	}

	wg.Wait()
	e.finish(jobID)
}

// runOne connects to a single server and runs the command, or — when script is
// true — pipes the payload to a remote shell (bash -s) so multi-line scripts
// (e.g. linpeas) run as a unit.
func (e *Executor) runOne(jobID string, srv models.Server, command string, script bool) models.BulkResult {
	start := time.Now()
	res := models.BulkResult{
		JobID:      jobID,
		ServerID:   srv.ID,
		ServerName: srv.Name,
		ExitCode:   -1,
	}

	// Scripts (recon tools like linpeas) run far longer than a one-line command.
	timeout := e.Timeout
	if script && timeout < 10*time.Minute {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Decrypt credentials for use (encrypted at rest).
	srv.SSHKey = e.Cipher.DecryptPtr(srv.SSHKey)
	srv.SSHPassword = e.Cipher.DecryptPtr(srv.SSHPassword)

	conn, err := e.dial(ctx, srv)
	if err != nil {
		res.Status = models.BulkStatusUnreachable
		res.Stderr = err.Error()
		res.DurationMS = int(time.Since(start).Milliseconds())
		return res
	}
	defer conn.Close()

	client, err := newClient(conn, srv)
	if err != nil {
		res.Status = models.BulkStatusError
		res.Stderr = err.Error()
		res.DurationMS = int(time.Since(start).Milliseconds())
		return res
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		res.Status = models.BulkStatusError
		res.Stderr = err.Error()
		res.DurationMS = int(time.Since(start).Milliseconds())
		return res
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	// Script mode: feed the payload to `bash -s` over stdin so an entire script
	// runs as one unit. Command mode runs the line directly.
	remoteCmd := command
	if script {
		session.Stdin = strings.NewReader(command + "\n")
		remoteCmd = "bash -s"
	}

	// Enforce the per-host timeout around Run.
	runErr := make(chan error, 1)
	go func() { runErr <- session.Run(remoteCmd) }()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		res.Status = models.BulkStatusTimeout
		res.Stderr = "timeout exceeded"
	case err := <-runErr:
		res.Stdout = stdout.String()
		res.Stderr = stderr.String()
		if err == nil {
			res.Status = models.BulkStatusOK
			res.ExitCode = 0
		} else if ee, ok := err.(*ssh.ExitError); ok {
			res.Status = models.BulkStatusOK // command ran, nonzero exit
			res.ExitCode = ee.ExitStatus()
		} else {
			res.Status = models.BulkStatusError
			if res.Stderr == "" {
				res.Stderr = err.Error()
			}
		}
	}

	res.DurationMS = int(time.Since(start).Milliseconds())
	return res
}

// dial returns a transport conn for the server (agent tunnel or direct TCP).
func (e *Executor) dial(ctx context.Context, srv models.Server) (net.Conn, error) {
	if srv.ConnectionMode == models.ModeAgent {
		return e.Registry.Dial(srv.ID)
	}
	d := net.Dialer{}
	addr := net.JoinHostPort(srv.Host, fmt.Sprintf("%d", srv.Port))
	return d.DialContext(ctx, "tcp", addr)
}

// newClient performs the SSH handshake for bulk execution.
func newClient(conn net.Conn, srv models.Server) (*ssh.Client, error) {
	user := "root"
	if srv.SSHUser != nil && *srv.SSHUser != "" {
		user = *srv.SSHUser
	}
	var methods []ssh.AuthMethod
	if srv.SSHKey != nil && *srv.SSHKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(*srv.SSHKey))
		if err != nil {
			return nil, fmt.Errorf("parse ssh key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if srv.SSHPassword != nil && *srv.SSHPassword != "" {
		methods = append(methods, ssh.Password(*srv.SSHPassword))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("no SSH credentials configured")
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            methods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: verify host keys
		Timeout:         15 * time.Second,
	}
	addr := net.JoinHostPort(srv.Host, fmt.Sprintf("%d", srv.Port))
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// resolveServers loads all servers belonging to the group.
func (e *Executor) resolveServers(groupID string) ([]models.Server, error) {
	rows, err := e.DB.Query(
		`SELECT s.id, s.name, s.host, s.port, s.protocol, s.connection_mode,
		        s.status, s.ssh_user, s.ssh_key, s.ssh_password
		 FROM servers s
		 JOIN group_members gm ON gm.server_id = s.id
		 WHERE gm.group_id = $1`, groupID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.Server
	for rows.Next() {
		var s models.Server
		if err := rows.Scan(
			&s.ID, &s.Name, &s.Host, &s.Port, &s.Protocol, &s.ConnectionMode,
			&s.Status, &s.SSHUser, &s.SSHKey, &s.SSHPassword,
		); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// store persists a single result row.
func (e *Executor) store(res models.BulkResult) {
	_, err := e.DB.Exec(
		`INSERT INTO bulk_results (job_id, server_id, status, stdout, stderr, exit_code, duration_ms)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		res.JobID, res.ServerID, res.Status, res.Stdout, res.Stderr, res.ExitCode, res.DurationMS,
	)
	if err != nil {
		log.Printf("bulk store result failed: %v", err)
	}
}

// finish marks the job done and closes all subscriber channels.
func (e *Executor) finish(jobID string) {
	_, _ = e.DB.Exec(`UPDATE bulk_jobs SET status = $1 WHERE id = $2`, "done", jobID)
	e.mu.Lock()
	subs := e.subscribers[jobID]
	delete(e.subscribers, jobID)
	e.mu.Unlock()
	for _, ch := range subs {
		close(ch)
	}
}
