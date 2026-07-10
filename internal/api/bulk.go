package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/shellwarden/shellwarden/internal/auth"
	"github.com/shellwarden/shellwarden/internal/models"
)

type bulkReq struct {
	GroupID string `json:"group_id"`
	Command string `json:"command"`
	Script  bool   `json:"script"` // run Command as a multi-line script via bash -s
}

// CreateBulk creates a bulk job and kicks off async execution.
func (a *API) CreateBulk(w http.ResponseWriter, r *http.Request) {
	var req bulkReq
	if err := decodeJSON(r, &req); err != nil || req.GroupID == "" || req.Command == "" {
		writeErr(w, http.StatusBadRequest, "group_id and command required")
		return
	}

	var userID interface{}
	if claims, ok := auth.ClaimsFrom(r.Context()); ok {
		userID = claims.UserID
	}

	var jobID string
	err := a.DB.QueryRow(
		`INSERT INTO bulk_jobs (user_id, group_id, command, is_script) VALUES ($1, $2, $3, $4) RETURNING id`,
		userID, req.GroupID, req.Command, req.Script,
	).Scan(&jobID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not create job")
		return
	}

	go a.Executor.Run(jobID, req.GroupID, req.Command, req.Script)

	writeJSON(w, http.StatusCreated, map[string]string{"job_id": jobID, "status": "running"})
}

// GetBulk returns a job and all of its results so far.
func (a *API) GetBulk(w http.ResponseWriter, r *http.Request) {
	jobID := mux.Vars(r)["job_id"]

	var job models.BulkJob
	err := a.DB.QueryRow(
		`SELECT id, user_id, group_id, command, created_at, status FROM bulk_jobs WHERE id = $1`,
		jobID,
	).Scan(&job.ID, &job.UserID, &job.GroupID, &job.Command, &job.CreatedAt, &job.Status)
	if err != nil {
		writeErr(w, http.StatusNotFound, "job not found")
		return
	}

	results := a.bulkResults(jobID)
	writeJSON(w, http.StatusOK, map[string]interface{}{"job": job, "results": results})
}

func (a *API) bulkResults(jobID string) []models.BulkResult {
	rows, err := a.DB.Query(
		`SELECT r.id, r.job_id, r.server_id, COALESCE(s.name,''), r.status, r.stdout,
		        r.stderr, r.exit_code, r.duration_ms, r.created_at
		 FROM bulk_results r LEFT JOIN servers s ON s.id = r.server_id
		 WHERE r.job_id = $1 ORDER BY r.created_at`, jobID,
	)
	if err != nil {
		return []models.BulkResult{}
	}
	defer rows.Close()
	out := []models.BulkResult{}
	for rows.Next() {
		var br models.BulkResult
		if err := rows.Scan(&br.ID, &br.JobID, &br.ServerID, &br.ServerName, &br.Status,
			&br.Stdout, &br.Stderr, &br.ExitCode, &br.DurationMS, &br.CreatedAt); err == nil {
			out = append(out, br)
		}
	}
	return out
}

// StreamBulk streams per-host results to the client over SSE as they complete.
func (a *API) StreamBulk(w http.ResponseWriter, r *http.Request) {
	jobID := mux.Vars(r)["job_id"]

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Subscribe before replaying stored results to avoid missing any in flight.
	ch, cancel := a.Executor.Subscribe(jobID)
	defer cancel()

	// Replay results already persisted (job may have partially/fully completed).
	for _, res := range a.bulkResults(jobID) {
		sendSSE(w, res)
	}
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case res, open := <-ch:
			if !open {
				// Executor finished and closed the channel.
				fmt.Fprintf(w, "event: done\ndata: {}\n\n")
				flusher.Flush()
				return
			}
			sendSSE(w, res)
			flusher.Flush()
		}
	}
}

func sendSSE(w http.ResponseWriter, res models.BulkResult) {
	b, err := json.Marshal(res)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", b)
}
