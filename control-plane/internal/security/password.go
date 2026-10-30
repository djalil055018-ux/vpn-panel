package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"
)

const passwordPrefix = "argon2id$v=19$m=19456,t=2,p=1$"

func ValidNewPassword(password string) bool {
	return utf8.ValidString(password) && utf8.RuneCountInString(password) >= 15 && len(password) <= 1024
}

func HashPassword(password string) (string, error) {
	if !ValidNewPassword(password) {
		return "", errors.New("password must contain at least 15 characters and at most 1024 bytes")
	}
	return RehashVerifiedPassword(password)
}

// Call only after verifying an existing credential. This permits upgrading a
// legacy hash without silently changing the existing password policy at login.
func RehashVerifiedPassword(password string) (string, error) {
	if password == "" || len(password) > 1024 || !utf8.ValidString(password) {
		return "", errors.New("invalid password")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, 2, 19456, 1, 32)
	return passwordPrefix + base64.RawURLEncoding.EncodeToString(salt) + "$" + base64.RawURLEncoding.EncodeToString(key), nil
}

// Only the current fixed Argon2id parameters and the original Node scrypt
// format are accepted. Stored data cannot request unbounded KDF resource use.
func passwordParts(encoded string) (salt, key []byte, legacy bool, ok bool) {
	if len(encoded) > 256 {
		return nil, nil, false, false
	}
	var parts []string
	if strings.HasPrefix(encoded, passwordPrefix) {
		parts = strings.Split(strings.TrimPrefix(encoded, passwordPrefix), "$")
	} else {
		legacy = true
		parts = strings.Split(encoded, ":")
	}
	if len(parts) != 2 {
		return nil, nil, false, false
	}
	salt, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return nil, nil, false, false
	}
	key, err = base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return nil, nil, false, false
	}
	if len(salt) < 16 || len(salt) > 64 || (len(key) != 32 && !(legacy && len(key) == 64)) {
		return nil, nil, false, false
	}
	return salt, key, legacy, true
}

func ValidPasswordHash(encoded string) bool { _, _, _, ok := passwordParts(encoded); return ok }
func PasswordNeedsUpgrade(encoded string) bool {
	_, _, legacy, ok := passwordParts(encoded)
	return ok && legacy
}

func VerifyPassword(password, encoded string) bool {
	if len(password) > 1024 || !utf8.ValidString(password) {
		return false
	}
	salt, expected, legacy, ok := passwordParts(encoded)
	if !ok {
		// Unknown usernames do comparable work without disclosing account existence.
		_ = argon2.IDKey([]byte(password), []byte("vpn-dummy-salt-16"), 2, 19456, 1, 32)
		return false
	}
	var actual []byte
	if legacy {
		var err error
		actual, err = scrypt.Key([]byte(password), salt, 16384, 8, 1, len(expected))
		if err != nil {
			return false
		}
	} else {
		actual = argon2.IDKey([]byte(password), salt, 2, 19456, 1, 32)
	}
	return subtle.ConstantTimeCompare(actual, expected) == 1
}
