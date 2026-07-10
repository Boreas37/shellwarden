package auth

import "testing"

func TestJWTIssueParse(t *testing.T) {
	m := NewManager("super-secret")
	tok, err := m.Issue("uid-1", "alice", "admin")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, err := m.Parse(tok)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if claims.UserID != "uid-1" || claims.Username != "alice" || claims.Role != "admin" {
		t.Fatalf("claims mismatch: %+v", claims)
	}
}

func TestJWTWrongSecretRejected(t *testing.T) {
	tok, _ := NewManager("secret-a").Issue("u", "n", "operator")
	if _, err := NewManager("secret-b").Parse(tok); err == nil {
		t.Fatalf("token signed with different secret should not validate")
	}
}

func TestJWTGarbageRejected(t *testing.T) {
	if _, err := NewManager("s").Parse("not.a.jwt"); err == nil {
		t.Fatalf("garbage token accepted")
	}
}
