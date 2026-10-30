package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var errMFASecret = errors.New("MFA key unavailable or invalid")
var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func NewTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return totpEncoding.EncodeToString(raw), nil
}

// RFC 6238, SHA-1, six decimal digits, 30-second step and Unix epoch.
func TOTPCode(secret string, step int64) (string, error) {
	raw, err := totpEncoding.DecodeString(secret)
	if err != nil || len(raw) != 20 || step < 0 {
		return "", errMFASecret
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, raw)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000), nil
}

// The caller atomically stores the returned step alongside the accepted action.
// A code accepted in the small clock-skew window cannot be accepted a second time.
func VerifyTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	if len(code) != 6 || now.Unix() < 30 {
		return -1, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return -1, false
		}
	}
	current := now.Unix() / 30
	matched := int64(-1)
	for step := current - 1; step <= current+1; step++ {
		expected, err := TOTPCode(secret, step)
		if err != nil {
			return -1, false
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 && step > lastStep {
			matched = step
		}
	}
	return matched, matched >= 0
}

func TOTPProvisioningURL(secret, username string) string {
	parameters := url.Values{"secret": {secret}, "issuer": {"VPN Platform"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + url.PathEscape("VPN Platform:"+username) + "?" + parameters.Encode()
}

func mfaCipher(master string) (cipher.AEAD, error) {
	key, err := base64.RawURLEncoding.DecodeString(master)
	if err != nil || len(key) != 32 {
		return nil, errMFASecret
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errMFASecret
	}
	return cipher.NewGCM(block)
}
func MFAKeyReady(master string) bool { _, err := mfaCipher(master); return err == nil }
func SealMFASecret(master, accountID, secret string) (string, error) {
	a, err := mfaCipher(master)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	raw := a.Seal(nonce, nonce, []byte(secret), []byte("vpn-admin-mfa-v1:"+accountID))
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
func OpenMFASecret(master, accountID, encrypted string) (string, error) {
	a, err := mfaCipher(master)
	if err != nil {
		return "", err
	}
	raw, err := base64.RawURLEncoding.DecodeString(encrypted)
	if err != nil || len(raw) < a.NonceSize()+a.Overhead() {
		return "", errMFASecret
	}
	plain, err := a.Open(nil, raw[:a.NonceSize()], raw[a.NonceSize():], []byte("vpn-admin-mfa-v1:"+accountID))
	if err != nil {
		return "", errMFASecret
	}
	return string(plain), nil
}

func NewRecoveryCodes(accountID string) (codes, hashes []string, err error) {
	for i := 0; i < 10; i++ {
		raw := make([]byte, 16)
		if _, err = rand.Read(raw); err != nil {
			return nil, nil, err
		}
		value := hex.EncodeToString(raw)
		code := value[:8] + "-" + value[8:16] + "-" + value[16:24] + "-" + value[24:]
		hash, _ := RecoveryCodeHash(accountID, code)
		codes = append(codes, code)
		hashes = append(hashes, hash)
	}
	return codes, hashes, nil
}
func RecoveryCodeHash(accountID, code string) (string, bool) {
	value := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(code)), "-", "")
	if len(value) != 32 {
		return "", false
	}
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 16 {
		return "", false
	}
	sum := sha256.Sum256([]byte("vpn-admin-recovery-v1:" + accountID + ":" + value))
	return hex.EncodeToString(sum[:]), true
}
