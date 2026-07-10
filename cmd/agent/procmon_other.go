//go:build !linux

package main

import "errors"

// monitorExecConnector is unavailable off Linux; callers fall back to polling.
func monitorExecConnector(send func([]byte)) error {
	return errors.New("proc connector only supported on linux")
}
