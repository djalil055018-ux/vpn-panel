package hysteria

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"
)

var ErrStatistics = errors.New("Hysteria statistics unavailable or invalid")

type Usage struct{ UploadBytes, DownloadBytes uint64 }
type Statistics struct {
	base, secret string
	http         *http.Client
}

func NewStatistics(port int, secret string) (*Statistics, error) {
	if port < 1024 || port > 65535 || !credential.MatchString(secret) {
		return nil, ErrStatistics
	}
	return &Statistics{base: fmt.Sprintf("http://127.0.0.1:%d", port), secret: secret, http: &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (s *Statistics) request(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	r, err := http.NewRequestWithContext(ctx, method, s.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, ErrStatistics
	}
	r.Header.Set("Authorization", s.secret)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	response, err := s.http.Do(r)
	if err != nil {
		return nil, ErrStatistics
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, ErrStatistics
	}
	const limit = 4 * 1024 * 1024
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || len(raw) > limit {
		return nil, ErrStatistics
	}
	return raw, nil
}

// Upstream2.12.2's traffic API uses client-oriented counters: tx is upload and
// rx is download. Native asymmetric-payload tests pin this mapping. Never clear
// counters: the agent's durable delivery layer must perform epoch/delta handling.
func (s *Statistics) Traffic(ctx context.Context) (map[string]Usage, error) {
	raw, err := s.request(ctx, "GET", "/traffic", nil)
	if err != nil {
		return nil, err
	}
	var counts map[string]*struct {
		Tx *uint64 `json:"tx"`
		Rx *uint64 `json:"rx"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&counts) != nil || counts == nil || len(counts) > 100000 {
		return nil, ErrStatistics
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, ErrStatistics
	}
	out := make(map[string]Usage, len(counts))
	for id, count := range counts {
		if !identity.MatchString(id) || count == nil || count.Tx == nil || count.Rx == nil || *count.Tx > math.MaxInt64 || *count.Rx > math.MaxInt64-*count.Tx {
			return nil, ErrStatistics
		}
		out[id] = Usage{UploadBytes: *count.Tx, DownloadBytes: *count.Rx}
	}
	return out, nil
}

// Kick requests upstream's traffic-triggered disconnect marker. In 2.12.2 the
// first matching traffic event consumes the marker; another connection with the
// same ID may survive. Never acknowledge a durable revocation based on this call.
// AccessManager instead confirms a complete runtime stop for removed credentials.
func (s *Statistics) Kick(ctx context.Context, ids []string) error {
	if len(ids) > 100000 {
		return ErrStatistics
	}
	for _, id := range ids {
		if !identity.MatchString(id) {
			return ErrStatistics
		}
	}
	if len(ids) == 0 {
		return nil
	}
	body, err := json.Marshal(ids)
	if err != nil {
		return ErrStatistics
	}
	_, err = s.request(ctx, "POST", "/kick", body)
	return err
}
