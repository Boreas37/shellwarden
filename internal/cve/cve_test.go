package cve

import "testing"

func TestCVSSv3KnownVectors(t *testing.T) {
	cases := []struct {
		vec  string
		want string // bucket
	}{
		// CVE-2023-45853 (zlib/MiniZip) — 9.8 critical
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "critical"},
		// Local, low-impact — low/medium range
		{"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L", "low"},
		// Network, high impact, scope changed — critical
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "critical"},
	}
	for _, c := range cases {
		got := bucket(cvssV3Score(c.vec))
		if got != c.want {
			t.Errorf("vector %s: got %s (score %.1f), want %s", c.vec, got, cvssV3Score(c.vec), c.want)
		}
	}
}

func TestCVSSv3CriticalScore(t *testing.T) {
	// AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H is canonically 9.8.
	s := cvssV3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if s < 9.7 || s > 9.9 {
		t.Fatalf("expected ~9.8, got %.2f", s)
	}
}

func TestBucketBoundaries(t *testing.T) {
	for score, want := range map[float64]string{0: "", 3.9: "low", 4.0: "medium", 6.9: "medium", 7.0: "high", 9.0: "critical"} {
		if got := bucket(score); got != want {
			t.Errorf("bucket(%.1f)=%s want %s", score, got, want)
		}
	}
}
