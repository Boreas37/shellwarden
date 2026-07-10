// Package auditlog provides the single append path for audit_logs, maintaining
// a tamper-evident hash chain: each row's hash = SHA-256(prev_hash | event | data).
// Any edit/deletion/reordering breaks the chain and is detectable via Verify.
package auditlog

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"sync"
)

// mu serializes appends so the chain links to the true latest row.
var mu sync.Mutex

// Sink, if set, is invoked (non-blocking) after each append so events can be
// streamed to a SIEM. It is the gateway's responsibility to filter/forward.
var Sink func(eventType, data, session, server, user string)

func ns(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// chainHash computes the row hash from the previous hash and this row's content.
func chainHash(prev, eventType, data string) string {
	sum := sha256.Sum256([]byte(prev + "|" + eventType + "|" + data))
	return hex.EncodeToString(sum[:])
}

// Append writes one audit row, linking it into the hash chain.
func Append(db *sql.DB, sessionID, serverID, userID, eventType, data string) error {
	mu.Lock()
	defer mu.Unlock()

	var prev sql.NullString
	_ = db.QueryRow(`SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1`).Scan(&prev)

	hash := chainHash(prev.String, eventType, data)
	_, err := db.Exec(
		`INSERT INTO audit_logs (session_id, server_id, user_id, event_type, data, hash, prev_hash)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		ns(sessionID), ns(serverID), ns(userID), eventType, ns(data), hash,
		func() interface{} {
			if prev.Valid {
				return prev.String
			}
			return nil
		}(),
	)
	if err == nil && Sink != nil {
		go Sink(eventType, data, sessionID, serverID, userID)
	}
	return err
}

// VerifyResult reports the integrity of the chain.
type VerifyResult struct {
	OK         bool   `json:"ok"`
	Checked    int    `json:"checked"`
	BreakAtID  int64  `json:"break_at_id,omitempty"`
	BreakError string `json:"break_error,omitempty"`
}

// Verify walks the chain oldest→newest and confirms every row's hash matches
// SHA-256(prev_hash | event | data) and that prev_hash links to the prior row.
func Verify(db *sql.DB) (VerifyResult, error) {
	rows, err := db.Query(
		`SELECT id, event_type, COALESCE(data,''), COALESCE(hash,''), COALESCE(prev_hash,'')
		 FROM audit_logs ORDER BY id ASC`,
	)
	if err != nil {
		return VerifyResult{}, err
	}
	defer rows.Close()

	var prevHash string
	checked := 0
	for rows.Next() {
		var id int64
		var event, data, hash, prev string
		if err := rows.Scan(&id, &event, &data, &hash, &prev); err != nil {
			return VerifyResult{}, err
		}
		// Rows written before chaining existed (hash empty) are skipped but the
		// chain resumes from the last hashed row.
		if hash == "" {
			checked++
			continue
		}
		if prev != prevHash {
			return VerifyResult{OK: false, Checked: checked, BreakAtID: id, BreakError: "prev_hash does not link to prior row"}, nil
		}
		if chainHash(prev, event, data) != hash {
			return VerifyResult{OK: false, Checked: checked, BreakAtID: id, BreakError: "row hash mismatch (content altered)"}, nil
		}
		prevHash = hash
		checked++
	}
	return VerifyResult{OK: true, Checked: checked}, rows.Err()
}
