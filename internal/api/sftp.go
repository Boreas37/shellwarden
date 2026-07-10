package api

import (
	"io"
	"net/http"
	"path"
	"time"

	"github.com/gorilla/mux"
	"github.com/pkg/sftp"

	"github.com/shellwarden/shellwarden/internal/access"
	"github.com/shellwarden/shellwarden/internal/auth"
)

// jitOK enforces JIT access for non-admins when JIT is required.
func (a *API) jitOK(r *http.Request, serverID string) bool {
	if !a.Cfg.JITRequired {
		return true
	}
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok {
		return false
	}
	if claims.Role == RoleAdmin {
		return true
	}
	granted, _ := access.HasActiveGrant(a.DB, claims.UserID, serverID)
	return granted
}

// fileEntry is one directory listing item.
type fileEntry struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	IsDir   bool   `json:"is_dir"`
	ModTime string `json:"mod_time"`
}

// sftpClient opens an SFTP session to the server, returning it plus a closer.
func (a *API) sftpClient(serverID string) (*sftp.Client, func(), error) {
	client, err := a.SSHProxy.Connect(serverID)
	if err != nil {
		return nil, nil, err
	}
	sc, err := sftp.NewClient(client)
	if err != nil {
		client.Close()
		return nil, nil, err
	}
	return sc, func() { sc.Close(); client.Close() }, nil
}

// SFTPList lists a directory on the target.
func (a *API) SFTPList(w http.ResponseWriter, r *http.Request) {
	serverID := mux.Vars(r)["id"]
	if !a.jitOK(r, serverID) {
		writeErr(w, http.StatusForbidden, "access not approved (JIT)")
		return
	}
	dir := r.URL.Query().Get("path")
	if dir == "" {
		dir = "."
	}

	sc, closer, err := a.sftpClient(serverID)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "sftp connect failed: "+err.Error())
		return
	}
	defer closer()

	infos, err := sc.ReadDir(dir)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read dir failed: "+err.Error())
		return
	}
	entries := []fileEntry{}
	for _, fi := range infos {
		entries = append(entries, fileEntry{
			Name:    fi.Name(),
			Size:    fi.Size(),
			Mode:    fi.Mode().String(),
			IsDir:   fi.IsDir(),
			ModTime: fi.ModTime().Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"path": dir, "entries": entries})
}

// SFTPDownload streams a file from the target.
func (a *API) SFTPDownload(w http.ResponseWriter, r *http.Request) {
	serverID := mux.Vars(r)["id"]
	if !a.jitOK(r, serverID) {
		writeErr(w, http.StatusForbidden, "access not approved (JIT)")
		return
	}
	fpath := r.URL.Query().Get("path")
	if fpath == "" {
		writeErr(w, http.StatusBadRequest, "path required")
		return
	}

	sc, closer, err := a.sftpClient(serverID)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "sftp connect failed")
		return
	}
	defer closer()

	f, err := sc.Open(fpath)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "open failed: "+err.Error())
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+path.Base(fpath)+`"`)
	_, _ = io.Copy(w, f)
}

// SFTPUpload writes an uploaded file into a directory on the target.
func (a *API) SFTPUpload(w http.ResponseWriter, r *http.Request) {
	serverID := mux.Vars(r)["id"]
	if !a.jitOK(r, serverID) {
		writeErr(w, http.StatusForbidden, "access not approved (JIT)")
		return
	}
	dir := r.URL.Query().Get("path")
	if dir == "" {
		dir = "."
	}

	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid multipart form")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "file field required")
		return
	}
	defer file.Close()

	sc, closer, err := a.sftpClient(serverID)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "sftp connect failed")
		return
	}
	defer closer()

	dst := path.Join(dir, path.Base(header.Filename))
	out, err := sc.Create(dst)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "create failed: "+err.Error())
		return
	}
	defer out.Close()

	n, err := io.Copy(out, file)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "write failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"path": dst, "bytes": n})
}
