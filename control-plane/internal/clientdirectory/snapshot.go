// Package clientdirectory extracts a fixed display allowlist from a private
// immutable source snapshot. Original JSON never leaves this package.
package clientdirectory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
	"vpn-platform/internal/model"
)

var ErrSnapshot = errors.New("client directory snapshot is invalid")

type sourceUser struct {
	ID         int64           `json:"id"`
	TelegramID *int64          `json:"telegramId"`
	Tag        *string         `json:"tag"`
	Status     string          `json:"status"`
	LastReset  json.RawMessage `json:"lastTrafficResetAt"`
	Squads     []struct {
		Name string `json:"name"`
	} `json:"activeInternalSquads"`
	Traffic struct {
		First    json.RawMessage `json:"firstConnectedAt"`
		Online   json.RawMessage `json:"onlineAt"`
		LastNode *string         `json:"lastConnectedNodeUuid"`
		Lifetime *int64          `json:"lifetimeUsedTrafficBytes"`
	} `json:"userTraffic"`
}

func safeText(value string, maximum int) bool {
	return utf8.ValidString(value) && len(value) <= maximum && !strings.ContainsAny(value, "\x00\x7f\r\n")
}
func observation(raw json.RawMessage) (*model.DirectoryTime, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if string(raw) == "null" {
		return &model.DirectoryTime{}, nil
	}
	var at time.Time
	if json.Unmarshal(raw, &at) != nil || at.IsZero() || at.Year() < 1970 || at.Year() > 2100 {
		return nil, ErrSnapshot
	}
	return &model.DirectoryTime{Value: &at}, nil
}
func ProjectSnapshot(raw []byte, expectedSHA string) (map[int64]model.ClientDirectory, error) {
	digest := sha256.Sum256(raw)
	if len(raw) == 0 || len(raw) > 64<<20 || hex.EncodeToString(digest[:]) != expectedSHA {
		return nil, ErrSnapshot
	}
	var snapshot struct {
		CapturedAt time.Time       `json:"captured_at"`
		Users      []sourceUser    `json:"users"`
		Nodes      json.RawMessage `json:"nodes"`
	}
	if json.Unmarshal(raw, &snapshot) != nil || snapshot.CapturedAt.IsZero() || len(snapshot.Users) > 100000 {
		return nil, ErrSnapshot
	}
	type sourceNode struct {
		UUID string `json:"uuid"`
		Name string `json:"name"`
	}
	var nodes []sourceNode
	if len(snapshot.Nodes) > 0 && json.Unmarshal(snapshot.Nodes, &nodes) != nil {
		var envelope struct {
			Nodes []sourceNode `json:"nodes"`
		}
		if json.Unmarshal(snapshot.Nodes, &envelope) != nil {
			return nil, ErrSnapshot
		}
		nodes = envelope.Nodes
	}
	names := map[string]string{}
	for _, node := range nodes {
		if !safeText(node.Name, 256) {
			return nil, ErrSnapshot
		}
		names[node.UUID] = node.Name
	}
	out := map[int64]model.ClientDirectory{}
	for _, user := range snapshot.Users {
		if user.ID < 1 || user.ID > 9007199254740991 {
			return nil, ErrSnapshot
		}
		if _, exists := out[user.ID]; exists {
			return nil, ErrSnapshot
		}
		switch user.Status {
		case "ACTIVE", "EXPIRED", "DISABLED", "LIMITED":
		default:
			return nil, ErrSnapshot
		}
		if user.Tag != nil && !safeText(*user.Tag, 256) {
			return nil, ErrSnapshot
		}
		if user.TelegramID != nil && (*user.TelegramID < 0 || *user.TelegramID > 9007199254740991) {
			return nil, ErrSnapshot
		}
		if user.Traffic.Lifetime != nil && (*user.Traffic.Lifetime < 0 || *user.Traffic.Lifetime > 9000000000000000) {
			return nil, ErrSnapshot
		}
		id := user.ID
		at := snapshot.CapturedAt
		metadata := model.ClientDirectory{NumericID: &id, Tag: user.Tag, Groups: []string{}, LifetimeUsedBytes: user.Traffic.Lifetime, ConnectionState: "unknown", SourceStatus: user.Status, SourceObservedAt: &at}
		if user.TelegramID != nil {
			value := strconv.FormatInt(*user.TelegramID, 10)
			metadata.TelegramID = &value
		}
		if user.Traffic.LastNode != nil {
			if name, ok := names[*user.Traffic.LastNode]; ok {
				metadata.LastNodeName = &name
			}
		}
		seen := map[string]bool{}
		for _, squad := range user.Squads {
			if !safeText(squad.Name, 256) {
				return nil, ErrSnapshot
			}
			if squad.Name != "" && !seen[squad.Name] {
				metadata.Groups = append(metadata.Groups, squad.Name)
				seen[squad.Name] = true
			}
		}
		sort.Strings(metadata.Groups)
		var err error
		if metadata.FirstConnectedAt, err = observation(user.Traffic.First); err != nil {
			return nil, err
		}
		if metadata.LastOnlineAt, err = observation(user.Traffic.Online); err != nil {
			return nil, err
		}
		if metadata.LastTrafficResetAt, err = observation(user.LastReset); err != nil {
			return nil, err
		}
		// A snapshot never proves current online status, even if captured recently.
		if metadata.FirstConnectedAt != nil && metadata.FirstConnectedAt.Value == nil {
			metadata.ConnectionState = "never"
		}
		out[user.ID] = metadata
	}
	return out, nil
}
