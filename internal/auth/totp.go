package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP implements RFC 6238 (SHA-1, 6 digits, 30s step) — the algorithm used by
// Google Authenticator, Authy, 1Password, etc. No external dependencies.

const (
	totpDigits = 6
	totpStep   = 30 // seconds
)

// GenerateTOTPSecret returns a new base32 (no padding) secret.
func GenerateTOTPSecret() (string, error) {
	buf := make([]byte, 20) // 160-bit
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return strings.TrimRight(base32.StdEncoding.EncodeToString(buf), "="), nil
}

// TOTPCode computes the code for a secret at a given unix time.
func TOTPCode(secret string, t time.Time) (string, error) {
	key, err := base32.StdEncoding.DecodeString(padBase32(secret))
	if err != nil {
		return "", err
	}
	counter := uint64(t.Unix()) / totpStep

	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)

	h := hmac.New(sha1.New, key)
	h.Write(msg[:])
	sum := h.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	code %= 1_000_000
	return fmt.Sprintf("%06d", code), nil
}

// ValidateTOTP checks a code against the secret allowing ±1 step of clock skew.
func ValidateTOTP(secret, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	now := time.Now()
	for _, skew := range []time.Duration{0, -totpStep * time.Second, totpStep * time.Second} {
		if want, err := TOTPCode(secret, now.Add(skew)); err == nil && hmac.Equal([]byte(want), []byte(code)) {
			return true
		}
	}
	return false
}

// OTPAuthURL builds the otpauth:// URI used to render an enrollment QR code.
func OTPAuthURL(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", totpDigits))
	q.Set("period", fmt.Sprintf("%d", totpStep))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// padBase32 restores '=' padding stripped by GenerateTOTPSecret.
func padBase32(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if m := len(s) % 8; m != 0 {
		s += strings.Repeat("=", 8-m)
	}
	return s
}
