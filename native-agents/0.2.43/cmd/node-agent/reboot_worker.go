package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"time"

	"vpn-platform/internal/agent"
	"vpn-platform/internal/model"
)

const nodeRebootWorkerPollInterval = 10 * time.Second

var rebootJobUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

func nodeRebootUnitName(jobID string) (string, bool) {
	if !rebootJobUUID.MatchString(jobID) {
		return "", false
	}
	return "vpn-platform-node-reboot-" + jobID, true
}

func scheduleNodeReboot(ctx context.Context, jobID string) error {
	unit, ok := nodeRebootUnitName(jobID)
	if !ok {
		return fmt.Errorf("invalid reboot job")
	}
	systemdRun, err := exec.LookPath("systemd-run")
	if err != nil {
		return fmt.Errorf("systemd scheduler unavailable")
	}
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return fmt.Errorf("systemd reboot command unavailable")
	}
	cmd := exec.CommandContext(ctx, systemdRun,
		"--system",
		"--unit="+unit,
		"--on-active=20s",
		"--no-block",
		"--collect",
		systemctl,
		"reboot",
		"--no-wall",
	)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemd did not accept reboot timer")
	}
	return nil
}

func runNodeRebootWorker(ctx context.Context, client *agent.Client, agentToken, ownerInstanceID string) {
	log.Printf("node reboot worker started")
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		grant, exists, err := client.NodeRebootJobClaim(ctx, agentToken, ownerInstanceID)
		if err != nil {
			log.Printf("node reboot job claim failed")
		} else if exists {
			_, valid := nodeRebootUnitName(grant.JobID)
			result := model.NodeRebootJobResult{JobID: grant.JobID, OwnerInstanceID: ownerInstanceID, Status: "scheduled"}
			if !valid {
				result.Status = "failed"
				result.FailureCode = "scheduler_unavailable"
			} else {
				commandCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
				err = scheduleNodeReboot(commandCtx, grant.JobID)
				cancel()
				if err != nil {
					result.Status = "failed"
					result.FailureCode = "scheduler_unavailable"
				}
			}
			resultCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			if err := client.NodeRebootJobResult(resultCtx, agentToken, result); err != nil {
				log.Printf("node reboot job result could not be recorded job=%s", grant.JobID)
			}
			cancel()
		}

		select {
		case <-ctx.Done():
			return
		default:
			timer.Reset(nodeRebootWorkerPollInterval)
		}
	}
}
