package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"
	"time"
)

func TestBillingWebhookSignature(t *testing.T) {
	secret := "unit-test-payment-key-not-production"
	now := time.Unix(1800000000, 0)
	body := []byte(`{"status":"paid"}`)
	sign := func(at string, data []byte) string {
		m := hmac.New(sha256.New, []byte(secret))
		m.Write([]byte(at + "."))
		m.Write(data)
		return hex.EncodeToString(m.Sum(nil))
	}
	stamp := strconv.FormatInt(now.Unix(), 10)
	signature := sign(stamp, body)
	if !validBillingSignature(secret, stamp, signature, body, now) {
		t.Fatal("valid signature rejected")
	}
	for _, tc := range []struct {
		key, stamp, signature string
		body                  []byte
	}{
		{secret + "wrong", stamp, signature, body}, {secret, stamp, signature, []byte(`{"status":"paid","amount_minor":1}`)},
		{secret, "bad", signature, body}, {secret, stamp, "bad", body},
		{secret, strconv.FormatInt(now.Unix()-301, 10), sign(strconv.FormatInt(now.Unix()-301, 10), body), body},
		{secret, strconv.FormatInt(now.Unix()+31, 10), sign(strconv.FormatInt(now.Unix()+31, 10), body), body},
	} {
		if validBillingSignature(tc.key, tc.stamp, tc.signature, tc.body, now) {
			t.Fatal("invalid signature accepted")
		}
	}
}
