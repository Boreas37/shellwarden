package sshca

import (
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSignedCertVerifiesAgainstCA(t *testing.T) {
	pem, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	ca, err := Load(pem)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	signer, err := ca.SignUserCert("warden", 5*time.Minute)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	cert, ok := signer.PublicKey().(*ssh.Certificate)
	if !ok {
		t.Fatalf("signer public key is not a certificate")
	}

	caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ca.PublicKey()))
	if err != nil {
		t.Fatalf("parse ca pub: %v", err)
	}

	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return string(auth.Marshal()) == string(caPub.Marshal())
		},
	}
	if err := checker.CheckCert("warden", cert); err != nil {
		t.Fatalf("cert should verify for principal warden: %v", err)
	}
	if err := checker.CheckCert("intruder", cert); err == nil {
		t.Fatalf("cert must NOT verify for a different principal")
	}
}

func TestCertExpiry(t *testing.T) {
	pem, _ := Generate()
	ca, _ := Load(pem)
	signer, _ := ca.SignUserCert("u", 5*time.Minute)
	cert := signer.PublicKey().(*ssh.Certificate)
	if cert.ValidBefore <= cert.ValidAfter {
		t.Fatalf("ValidBefore must be after ValidAfter")
	}
	if cert.ValidBefore-cert.ValidAfter > uint64((7 * time.Minute).Seconds()) {
		t.Fatalf("certificate lifetime unexpectedly long")
	}
}
