package api

import (
	"testing"
	"time"
)

func TestBruteForceFiresOnceAtThreshold(t *testing.T) {
	b := newBruteForce()
	now := time.Now()
	fired := 0
	for i := 0; i < 8; i++ {
		if b.record("alice", now.Add(time.Duration(i)*time.Second)) {
			fired++
		}
	}
	if fired != 1 {
		t.Fatalf("expected exactly one alert at threshold, got %d", fired)
	}
}

func TestBruteForceWindowExpiry(t *testing.T) {
	b := newBruteForce()
	base := time.Now()
	// 4 failures, then a long gap, then 4 more — should NOT reach 5 in-window.
	for i := 0; i < 4; i++ {
		if b.record("bob", base.Add(time.Duration(i)*time.Second)) {
			t.Fatal("should not fire below threshold")
		}
	}
	later := base.Add(10 * time.Minute)
	for i := 0; i < 4; i++ {
		if b.record("bob", later.Add(time.Duration(i)*time.Second)) {
			t.Fatal("old failures should have expired from the window")
		}
	}
}
