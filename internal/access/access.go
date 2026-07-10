// Package access implements just-in-time access grant checks.
package access

import "database/sql"

// HasActiveGrant reports whether the user currently holds an approved,
// unexpired access grant for the server.
func HasActiveGrant(db *sql.DB, userID, serverID string) (bool, error) {
	var one int
	err := db.QueryRow(
		`SELECT 1 FROM access_requests
		 WHERE user_id = $1 AND server_id = $2 AND status = 'approved'
		   AND (expires_at IS NULL OR expires_at > NOW())
		 LIMIT 1`,
		userID, serverID,
	).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
