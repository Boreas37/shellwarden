package auth

import (
	"testing"
	"time"
)

func TestTOTPRoundTrip(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	code, err := TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	if !ValidateTOTP(secret, code) {
		t.Fatalf("freshly generated code did not validate")
	}
	if ValidateTOTP(secret, "000000") && code != "000000" {
		t.Fatalf("wrong code validated")
	}
}

// RFC 6238 Appendix B test vector (SHA-1, seed "12345678901234567890").
func TestTOTPKnownVector(t *testing.T) {
	// Base32 of the ASCII seed "12345678901234567890".
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	got, err := TOTPCode(secret, time.Unix(59, 0))
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	if got != "287082" {
		t.Fatalf("RFC6238 vector mismatch: got %s want 287082", got)
	}
}

func TestTOTPSkewWindow(t *testing.T) {
	secret, _ := GenerateTOTPSecret()
	// A code from the previous step should still validate (±1 window).
	prev, _ := TOTPCode(secret, time.Now().Add(-30*time.Second))
	if !ValidateTOTP(secret, prev) {
		t.Fatalf("previous-step code should validate within skew window")
	}
}
