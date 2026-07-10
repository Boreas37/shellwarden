//go:build !linux

package main

// collectPlatform is a no-op off Linux (disk/kernel collection is Linux-only).
func collectPlatform(t *telemetry) {}
