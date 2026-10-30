package model

import "encoding/base64"

const ShadowsocksMethod = "2022-blake3-aes-256-gcm"

type ShadowsocksSpec struct {
	Method    string `json:"method"`
	ServerKey string `json:"server_key"`
}

func ValidShadowsocksKey(value string) bool {
	key, err := base64.StdEncoding.Strict().DecodeString(value)
	return err == nil && len(key) == 32 && base64.StdEncoding.EncodeToString(key) == value
}
