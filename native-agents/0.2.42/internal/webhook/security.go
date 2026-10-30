package webhook

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
func sealCipher(master string) (cipher.AEAD, error) {
	key, err := base64.RawURLEncoding.DecodeString(master)
	if err != nil || len(key) != 32 {
		return nil, errors.New("webhook master key unavailable")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func Encrypt(master, id, secret string) (string, error) {
	a, err := sealCipher(master)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	raw := a.Seal(nonce, nonce, []byte(secret), []byte("vpn-webhook-v1:"+id))
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
func Decrypt(master, id, encrypted string) (string, error) {
	a, err := sealCipher(master)
	if err != nil {
		return "", err
	}
	raw, err := base64.RawURLEncoding.DecodeString(encrypted)
	if err != nil || len(raw) < a.NonceSize()+a.Overhead() {
		return "", errors.New("invalid webhook ciphertext")
	}
	plain, err := a.Open(nil, raw[:a.NonceSize()], raw[a.NonceSize():], []byte("vpn-webhook-v1:"+id))
	if err != nil {
		return "", errors.New("webhook key could not be decrypted")
	}
	return string(plain), nil
}
func MasterReady(master string) bool { _, err := sealCipher(master); return err == nil }
func Sign(secret, timestamp string, body []byte) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(timestamp))
	h.Write([]byte("."))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}
