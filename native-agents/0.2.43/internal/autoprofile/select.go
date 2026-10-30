// Package autoprofile chooses from an already authorized, healthy service pool.
// It never grants access, modifies a node, or falls back to a direct connection.
package autoprofile

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
)

type Endpoint struct {
	NodeID    string
	ServiceID string
	Healthy   bool
	// Lower values prefer a transport supported by the requesting application.
	Preference int
}

// Select distributes clients by node, not by the number of protocols a node
// happens to publish. Rendezvous hashing keeps the choice stable across refreshes
// and only moves clients whose selected node leaves the eligible pool.
// The caller must first apply tenant, subscription and client-format restrictions.
func Select(clientKey string, endpoints []Endpoint) (Endpoint, bool) {
	if clientKey == "" {
		return Endpoint{}, false
	}
	byNode := map[string]Endpoint{}
	for _, endpoint := range endpoints {
		if !endpoint.Healthy || endpoint.NodeID == "" || endpoint.ServiceID == "" {
			continue
		}
		current, exists := byNode[endpoint.NodeID]
		if !exists || endpoint.Preference < current.Preference ||
			(endpoint.Preference == current.Preference && endpoint.ServiceID < current.ServiceID) {
			byNode[endpoint.NodeID] = endpoint
		}
	}
	nodes := make([]string, 0, len(byNode))
	for id := range byNode {
		nodes = append(nodes, id)
	}
	sort.Strings(nodes)
	var selected Endpoint
	var highest uint64
	for index, id := range nodes {
		sum := sha256.Sum256([]byte("pauk-auto-node-v1\x00" + clientKey + "\x00" + id))
		score := binary.BigEndian.Uint64(sum[:8])
		if index == 0 || score > highest {
			highest, selected = score, byNode[id]
		}
	}
	return selected, len(nodes) > 0
}
