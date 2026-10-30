package security

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestTOTPReferenceVectorsAndReplay(t *testing.T) {
	// RFC 6238 appendix B SHA-1 vectors, reduced to the six-digit profile.
	secret := totpEncoding.EncodeToString([]byte("12345678901234567890"))
	for _, test := range []struct {
		at   int64
		code string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"}} {
		code, err := TOTPCode(secret, test.at/30)
		if err != nil || code != test.code {
			t.Fatalf("TOTP vector failed at %d", test.at)
		}
		step, ok := VerifyTOTP(secret, code, time.Unix(test.at, 0), -1)
		if !ok || step != test.at/30 {
			t.Fatal("valid TOTP rejected")
		}
		if _, ok = VerifyTOTP(secret, code, time.Unix(test.at, 0), step); ok {
			t.Fatal("used step accepted")
		}
	}
	now := time.Unix(1234567890, 0)
	old, _ := TOTPCode(secret, now.Unix()/30-2)
	if _, ok := VerifyTOTP(secret, old, now, -1); ok {
		t.Fatal("expired code accepted")
	}
	for _, bad := range []string{"", "12345", "1234567", "12 456", "１２３４５６"} {
		if _, ok := VerifyTOTP(secret, bad, now, -1); ok {
			t.Fatal("malformed code accepted")
		}
	}
}

func TestMFAEncryptionAndRecoveryScope(t *testing.T) {
	master := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := SealMFASecret(master, "account-a", secret)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SealMFASecret(master, "account-a", secret)
	if err != nil || second == encrypted {
		t.Fatal("encryption nonce reused")
	}
	plain, err := OpenMFASecret(master, "account-a", encrypted)
	if err != nil || plain != secret {
		t.Fatal("secret did not round trip")
	}
	if _, err = OpenMFASecret(master, "account-b", encrypted); err == nil {
		t.Fatal("ciphertext retargeted")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(encrypted)
	raw[len(raw)-1] ^= 1
	if _, err = OpenMFASecret(master, "account-a", base64.RawURLEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("corrupt ciphertext accepted")
	}
	if MFAKeyReady("bad") {
		t.Fatal("invalid master accepted")
	}
	codes, hashes, err := NewRecoveryCodes("account-a")
	if err != nil || len(codes) != 10 {
		t.Fatal("recovery generation failed")
	}
	seen := map[string]bool{}
	for i, code := range codes {
		hash, ok := RecoveryCodeHash("account-a", strings.ToUpper(code))
		if !ok || hash != hashes[i] || seen[hash] {
			t.Fatal("recovery normalization or uniqueness failed")
		}
		seen[hash] = true
		other, _ := RecoveryCodeHash("account-b", code)
		if other == hash {
			t.Fatal("recovery hash lacks account binding")
		}
	}
}
