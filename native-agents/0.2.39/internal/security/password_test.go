package security

import (
	"encoding/base64"
	"golang.org/x/crypto/scrypt"
	"strings"
	"testing"
)

func TestPasswordHashRoundtripAndBounds(t *testing.T) {
	password := "fixture password with spaces"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidPasswordHash(hash) || PasswordNeedsUpgrade(hash) || !VerifyPassword(password, hash) || VerifyPassword("incorrect password", hash) {
		t.Fatal("password verification failed")
	}
	other, err := HashPassword(password)
	if err != nil || other == hash {
		t.Fatal("salt was reused")
	}
	for _, value := range []string{"short", strings.Repeat("x", 1025), string([]byte{0xff})} {
		if _, err = HashPassword(value); err == nil {
			t.Fatal("invalid new password accepted")
		}
	}
	for _, value := range []string{"", passwordPrefix + "invalid", strings.Repeat("x", 257), strings.Replace(hash, "m=19456", "m=99999999", 1)} {
		if ValidPasswordHash(value) {
			t.Fatal("unbounded or malformed hash accepted")
		}
	}
}

func TestLegacyNodeScryptPasswordCompatibility(t *testing.T) {
	salt := []byte("fixture-salt-16b!")
	key, err := scrypt.Key([]byte("legacy password"), salt, 16384, 8, 1, 64)
	if err != nil {
		t.Fatal(err)
	}
	hash := base64.RawURLEncoding.EncodeToString(salt) + ":" + base64.RawURLEncoding.EncodeToString(key)
	if !ValidPasswordHash(hash) || !PasswordNeedsUpgrade(hash) || !VerifyPassword("legacy password", hash) || VerifyPassword("incorrect password", hash) {
		t.Fatal("legacy Node hash compatibility failed")
	}
}
