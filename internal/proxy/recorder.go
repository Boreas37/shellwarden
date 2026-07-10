package proxy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/shellwarden/shellwarden/internal/auditlog"
	"github.com/shellwarden/shellwarden/internal/models"
)

// Recorder wraps an io.ReadWriter (the SSH channel) and records every output
// chunk in two places: the asciinema v2 cast buffer (flushed to disk at session
// end) and the audit_logs table in real time.
//
// Convention: "o" (output, server->client) is recorded for the cast; both
// input and output are written to audit_logs.
type Recorder struct {
	db        *sql.DB
	sessionID string
	serverID  string
	userID    string

	width  int
	height int
	start  time.Time

	mu    sync.Mutex
	lines []string // buffered asciinema event lines

	BytesRead    int64 // server -> client (output)
	BytesWritten int64 // client -> server (input)

	// Publish, if set, receives every output chunk for live shadowing.
	Publish func([]byte)
}

// NewRecorder creates a recorder and writes the asciinema header line.
func NewRecorder(db *sql.DB, sessionID, serverID, userID string, width, height int) *Recorder {
	if width <= 0 {
		width = 220
	}
	if height <= 0 {
		height = 50
	}
	r := &Recorder{
		db:        db,
		sessionID: sessionID,
		serverID:  serverID,
		userID:    userID,
		width:     width,
		height:    height,
		start:     time.Now(),
	}

	header := map[string]interface{}{
		"version":   2,
		"width":     width,
		"height":    height,
		"timestamp": r.start.Unix(),
		"title":     sessionID,
	}
	if b, err := json.Marshal(header); err == nil {
		r.lines = append(r.lines, string(b))
	}
	return r
}

// elapsed returns seconds since session start.
func (r *Recorder) elapsed() float64 {
	return time.Since(r.start).Seconds()
}

// Bytes returns the total bytes transferred (read+written) so far, safely for
// concurrent readers (e.g. the idle watchdog).
func (r *Recorder) Bytes() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.BytesRead + r.BytesWritten
}

// RecordOutput records a server->client chunk to the cast and audit log.
func (r *Recorder) RecordOutput(p []byte) {
	r.mu.Lock()
	r.BytesRead += int64(len(p))
	r.appendEvent("o", p)
	r.mu.Unlock()
	if r.Publish != nil {
		r.Publish(p)
	}
	r.audit(models.EventOutput, string(p))
}

// RecordInput records a client->server chunk to the audit log (not the cast —
// asciinema replays output only).
func (r *Recorder) RecordInput(p []byte) {
	r.mu.Lock()
	r.BytesWritten += int64(len(p))
	r.mu.Unlock()
	r.audit(models.EventInput, string(p))
}

// appendEvent appends one asciinema event line. Caller holds r.mu.
func (r *Recorder) appendEvent(code string, p []byte) {
	evt := []interface{}{r.elapsed(), code, string(p)}
	if b, err := json.Marshal(evt); err == nil {
		r.lines = append(r.lines, string(b))
	}
}

// audit writes a single event row in real time via the append-only hash chain.
// Errors are logged-and-ignored to avoid disrupting the live session.
func (r *Recorder) audit(eventType, data string) {
	if r.db == nil {
		return
	}
	_ = auditlog.Append(r.db, r.sessionID, r.serverID, r.userID, eventType, data)
}

// Flush writes the accumulated cast to {dir}/{sessionID}.cast and returns its
// path.
func (r *Recorder) Flush(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir recordings: %w", err)
	}
	path := filepath.Join(dir, r.sessionID+".cast")

	r.mu.Lock()
	defer r.mu.Unlock()

	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	for _, line := range r.lines {
		if _, err := io.WriteString(f, line+"\n"); err != nil {
			return "", err
		}
	}
	return path, nil
}

// nullable converts an empty string to a SQL NULL.
func nullable(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// recordingReader wraps a reader, recording everything read as output.
type recordingReader struct {
	r   io.Reader
	rec *Recorder
}

func (rr *recordingReader) Read(p []byte) (int, error) {
	n, err := rr.r.Read(p)
	if n > 0 {
		rr.rec.RecordOutput(p[:n])
	}
	return n, err
}

// recordingWriter wraps a writer, recording everything written as input.
type recordingWriter struct {
	w   io.Writer
	rec *Recorder
}

func (rw *recordingWriter) Write(p []byte) (int, error) {
	n, err := rw.w.Write(p)
	if n > 0 {
		rw.rec.RecordInput(p[:n])
	}
	return n, err
}

// TeeOutput returns a reader that records server output as it is read.
func (r *Recorder) TeeOutput(src io.Reader) io.Reader { return &recordingReader{r: src, rec: r} }

// TeeInput returns a writer that records client input as it is written.
func (r *Recorder) TeeInput(dst io.Writer) io.Writer { return &recordingWriter{w: dst, rec: r} }
