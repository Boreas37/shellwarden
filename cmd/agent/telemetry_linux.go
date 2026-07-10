//go:build linux

package main

import "golang.org/x/sys/unix"

// collectPlatform fills disk usage (statfs on /) and kernel release (uname).
func collectPlatform(t *telemetry) {
	var st unix.Statfs_t
	if unix.Statfs("/", &st) == nil {
		bs := uint64(st.Bsize)
		t.DiskTotalGB = round1(float64(st.Blocks*bs) / 1e9)
		t.DiskFreeGB = round1(float64(st.Bavail*bs) / 1e9)
	}
	var u unix.Utsname
	if unix.Uname(&u) == nil {
		t.Kernel = utsString(u.Release[:])
	}
}

// utsString trims the NUL padding from a uname field ([65]byte on linux).
func utsString(b []byte) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	return string(b[:n])
}
