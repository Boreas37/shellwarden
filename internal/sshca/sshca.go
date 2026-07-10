// Package sshca implements a lightweight SSH certificate authority. The gateway
// signs short-lived user certificates per connection, so targets need only
// trust the CA public key (TrustedUserCAKeys) — no static passwords or keys are
// stored on hosts, and credentials cannot be exfiltrated.
package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

// CA holds the authority's signing key.
type CA struct {
	signer ssh.Signer
}

// Generate creates a new ed25519 CA and returns its private key in OpenSSH PEM.
func Generate() (string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, "shellwarden-ca")
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(block)), nil
}

// Load parses a CA from an OpenSSH PEM private key.
func Load(privPEM string) (*CA, error) {
	signer, err := ssh.ParsePrivateKey([]byte(privPEM))
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}
	return &CA{signer: signer}, nil
}

// PublicKey returns the CA public key in authorized_keys format — the value
// targets put in TrustedUserCAKeys.
func (c *CA) PublicKey() string {
	return string(ssh.MarshalAuthorizedKey(c.signer.PublicKey()))
}

// SignUserCert mints an ephemeral keypair and signs a short-lived user
// certificate valid for the given principal (the target login user). The
// returned signer authenticates with that certificate.
func (c *CA) SignUserCert(principal string, ttl time.Duration) (ssh.Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	cert := &ssh.Certificate{
		Key:             sshPub,
		Serial:          uint64(now.UnixNano()),
		CertType:        ssh.UserCert,
		KeyId:           "shellwarden/" + principal,
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(now.Add(-1 * time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(ttl).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-pty":             "",
				"permit-port-forwarding": "",
			},
		},
	}
	if err := cert.SignCert(rand.Reader, c.signer); err != nil {
		return nil, fmt.Errorf("sign cert: %w", err)
	}

	ephSigner, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		return nil, err
	}
	return ssh.NewCertSigner(cert, ephSigner)
}
