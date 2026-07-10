package auditlog

import "testing"

// The chain hash must be deterministic and order/content sensitive.
func TestChainHashDeterministic(t *testing.T) {
	a := chainHash("prev", "output", "ls -la")
	b := chainHash("prev", "output", "ls -la")
	if a != b {
		t.Fatalf("chainHash not deterministic")
	}
}

func TestChainHashContentSensitive(t *testing.T) {
	base := chainHash("p", "output", "data")
	if chainHash("p", "output", "DATA") == base {
		t.Fatalf("content change did not alter hash")
	}
	if chainHash("p", "input", "data") == base {
		t.Fatalf("event-type change did not alter hash")
	}
	if chainHash("p2", "output", "data") == base {
		t.Fatalf("prev-hash change did not alter hash (chain not linked)")
	}
}
