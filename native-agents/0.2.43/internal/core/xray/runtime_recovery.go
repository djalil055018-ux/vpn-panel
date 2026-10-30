package xray

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"vpn-platform/internal/model"
)

func (d *Driver) RuntimeRecoveryInfo() model.RuntimeRecoveryInfo {
	info := model.RuntimeRecoveryInfo{
		CurrentCoreVersion: d.CurrentVersion(),
	}

	entries, err := os.ReadDir(
		d.snapshotDir(),
	)
	if err != nil {
		return info
	}

	var latestValid int64 = -1

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		info.SnapshotCount++

		id := entry.Name()

		timestamp, err := strconv.ParseInt(
			id,
			10,
			64,
		)
		if err != nil {
			continue
		}

		dir := filepath.Join(
			d.snapshotDir(),
			id,
		)

		raw, err := os.ReadFile(
			filepath.Join(
				dir,
				"metadata.json",
			),
		)
		if err != nil {
			continue
		}

		var metadata snapshotMetadata

		if err := json.Unmarshal(
			raw,
			&metadata,
		); err != nil {
			continue
		}

		version := strings.TrimSpace(
			metadata.Version,
		)

		if version == "" {
			continue
		}

		binaryInfo, err := os.Stat(
			d.binary(version),
		)
		if err != nil || binaryInfo.IsDir() {
			continue
		}

		configInfo, err := os.Stat(
			filepath.Join(
				dir,
				"config.json",
			),
		)
		if err != nil || configInfo.IsDir() {
			continue
		}

		if timestamp <= latestValid {
			continue
		}

		latestValid = timestamp
		info.LatestSnapshotID = id
		info.LastKnownGoodCoreVersion = version
		info.RollbackReady = true
	}

	return info
}
