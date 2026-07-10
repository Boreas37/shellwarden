// Package crypto provides transparent encryption-at-rest for stored secrets
// (SSH passwords and private keys). Ciphertext is tagged with a version prefix
// so plaintext written by older builds is still readable (gradual migration).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"strings"
)

const prefix = "enc:v1:"

// Cipher wraps an AES-256-GCM AEAD keyed from the configured secret.
type Cipher struct {
	aead cipher.AEAD
}

// New derives a 256-bit key from secret (SHA-256) and builds an AES-GCM cipher.
func New(secret string) *Cipher {
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err) // impossible for a 32-byte key
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return &Cipher{aead: aead}
}

// Encrypt returns a versioned, base64 ciphertext. Empty input stays empty so a
// blank credential remains "no credential".
func (c *Cipher) Encrypt(plain string) string {
	if plain == "" {
		return ""
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return plain // extremely unlikely; avoid data loss
	}
	ct := c.aead.Seal(nonce, nonce, []byte(plain), nil)
	return prefix + base64.StdEncoding.EncodeToString(ct)
}

// EncryptPtr encrypts the pointed-to string in place semantics: returns a new
// pointer with ciphertext, or nil/empty preserved. nil and empty mean "unset".
func (c *Cipher) EncryptPtr(p *string) *string {
	if p == nil {
		return nil
	}
	enc := c.Encrypt(*p)
	return &enc
}

// Decrypt reverses Encrypt. Values without the version prefix are returned
// unchanged (legacy plaintext). On any failure it returns "".
func (c *Cipher) Decrypt(s string) string {
	if !strings.HasPrefix(s, prefix) {
		return s
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, prefix))
	if err != nil {
		return ""
	}
	ns := c.aead.NonceSize()
	if len(raw) < ns {
		return ""
	}
	pt, err := c.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return ""
	}
	return string(pt)
}

// DecryptPtr decrypts a *string credential for use, preserving nil.
func (c *Cipher) DecryptPtr(p *string) *string {
	if p == nil {
		return nil
	}
	dec := c.Decrypt(*p)
	return &dec
}
