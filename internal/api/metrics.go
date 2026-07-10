package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

// MetricPoint is one time-series sample for the resource dashboard.
type MetricPoint struct {
	TS          string  `json:"ts"`
	CPUPct      float64 `json:"cpu_pct"`
	MemUsedPct  float64 `json:"mem_used_pct"`
	DiskUsedPct float64 `json:"disk_used_pct"`
	NetRxKBs    float64 `json:"net_rx_kbs"`
	NetTxKBs    float64 `json:"net_tx_kbs"`
	Load1       float64 `json:"load1"`
}

// ServerMetrics returns the metric time series for a host (default last 60 min).
func (a *API) ServerMetrics(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	minutes := 60
	if v := r.URL.Query().Get("minutes"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1440 {
			minutes = n
		}
	}
	rows, err := a.DB.Query(
		`SELECT ts, COALESCE(cpu_pct,0), COALESCE(mem_used_pct,0), COALESCE(disk_used_pct,0),
		        COALESCE(net_rx_kbs,0), COALESCE(net_tx_kbs,0), COALESCE(load1,0)
		 FROM server_metrics
		 WHERE server_id = $1 AND ts > NOW() - ($2 || ' minutes')::interval
		 ORDER BY ts ASC`, id, minutes)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()

	out := []MetricPoint{}
	for rows.Next() {
		var p MetricPoint
		var ts time.Time
		if rows.Scan(&ts, &p.CPUPct, &p.MemUsedPct, &p.DiskUsedPct, &p.NetRxKBs, &p.NetTxKBs, &p.Load1) == nil {
			p.TS = ts.Format(time.RFC3339)
			out = append(out, p)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// ServerVulns returns the latest vulnerability scan for a host.
func (a *API) ServerVulns(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var scan *string
	var scannedAt *time.Time
	if err := a.DB.QueryRow(
		`SELECT vuln_scan, vuln_scanned_at FROM servers WHERE id = $1`, id,
	).Scan(&scan, &scannedAt); err != nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if scan == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"scanned": false})
		return
	}
	var parsed json.RawMessage = json.RawMessage(*scan)
	writeJSON(w, http.StatusOK, map[string]interface{}{"scanned": true, "scan": parsed})
}
