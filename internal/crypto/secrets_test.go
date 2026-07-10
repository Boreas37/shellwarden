package crypto

import "testing"

func TestEncryptDecryptRoundTrip(t *testing.T) {
	c := New("test-secret-key")
	for _, plain := range []string{"hunter2", "", "a very long passphrase with spaces and symbols !@#$%"} {
		enc := c.Encrypt(plain)
		if plain != "" && enc == plain {
			t.Fatalf("ciphertext equals plaintext for %q", plain)
		}
		if got := c.Decrypt(enc); got != plain {
			t.Fatalf("roundtrip: got %q want %q", got, plain)
		}
	}
}

func TestDecryptLegacyPlaintext(t *testing.T) {
	c := New("k")
	// Values without the version prefix are treated as legacy plaintext.
	if got := c.Decrypt("legacy-plain"); got != "legacy-plain" {
		t.Fatalf("legacy passthrough failed: %q", got)
	}
}

func TestDifferentKeysDoNotDecrypt(t *testing.T) {
	enc := New("key-a").Encrypt("secret")
	if got := New("key-b").Decrypt(enc); got == "secret" {
		t.Fatalf("ciphertext decrypted under wrong key")
	}
}

func TestNonceUniqueness(t *testing.T) {
	c := New("k")
	if c.Encrypt("same") == c.Encrypt("same") {
		t.Fatalf("identical plaintexts produced identical ciphertext (nonce reuse)")
	}
}
