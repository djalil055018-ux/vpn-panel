package model

// Cascade credentials belong to node desired state, never to the public list
// of cascade definitions. Client subscriptions contain only the entry profile.
type XrayCascadesSpec struct {
	Version int                `json:"version"`
	Entries []XrayCascadeEntry `json:"entries,omitempty"`
	Exits   []XrayCascadeExit  `json:"exits,omitempty"`
}

type XrayCascadeEntry struct {
	ID        string              `json:"id"`
	ServiceID string              `json:"service_id"`
	Port      int                 `json:"port"`
	Clients   []ClientSpec        `json:"clients"`
	Exit      XrayCascadeEndpoint `json:"exit"`
}

type XrayCascadeExit struct {
	ID        string `json:"id"`
	ServiceID string `json:"service_id"`
	ClientID  string `json:"client_id"`
}

type XrayCascadeEndpoint struct {
	Address             string `json:"address"`
	Port                int    `json:"port"`
	ClientID            string `json:"client_id"`
	ServerName          string `json:"server_name"`
	PublicKey           string `json:"public_key"`
	ShortID             string `json:"short_id"`
	Fingerprint         string `json:"fingerprint"`
	Flow                string `json:"flow,omitempty"`
	ConnectRaceIP       string `json:"connect_race_ip,omitempty"`
	ConnectRaceAttempts int    `json:"connect_race_attempts,omitempty"`
}
