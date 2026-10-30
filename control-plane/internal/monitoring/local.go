package monitoring

import (
	"encoding/json"
	"io"
	"os"
	"vpn-platform/internal/model"
)

func AddLocalStatus(s *model.OperationsStatus) {
	s.ControlPlaneFreeBytes = freeBytes()
	f, err := os.Open("/var/lib/vpn-platform/operations/control-plane-backup.json")
	if err != nil {
		return
	}
	defer f.Close()
	var backup model.BackupStatus
	if json.NewDecoder(io.LimitReader(f, 65536)).Decode(&backup) == nil {
		s.ControlPlaneBackup = &backup
	}
}
