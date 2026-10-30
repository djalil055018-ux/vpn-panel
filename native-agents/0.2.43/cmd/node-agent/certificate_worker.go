package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"vpn-platform/internal/agent"
	"vpn-platform/internal/model"
)

const certificateWorkerPollInterval = 10 * time.Second

func safeCertificateError(
	err error,
) string {
	if err == nil {
		return ""
	}

	value :=
		strings.TrimSpace(
			err.Error(),
		)

	const maxLength = 1500

	if len(value) >
		maxLength {
		value =
			value[:maxLength]
	}

	return value
}

func renewCertificateLease(
	ctx context.Context,
	client *agent.Client,
	agentToken string,
	ownerInstanceID string,
	grant model.CertificateJobGrant,
	cancel context.CancelFunc,
) {
	seconds :=
		grant.RenewAfterSeconds

	if seconds < 30 {
		seconds = 300
	}

	ticker :=
		time.NewTicker(
			time.Duration(seconds) *
				time.Second,
		)

	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			renewed, err :=
				client.CertificateJobRenew(
					ctx,
					agentToken,
					model.CertificateJobLeaseRenewRequest{
						JobID:           grant.JobID,
						OwnerInstanceID: ownerInstanceID,
						LeaseToken:      grant.LeaseToken,
					},
				)

			if err != nil {
				log.Printf(
					"certificate job lease renewal failed job=%s: %v",
					grant.JobID,
					err,
				)

				cancel()
				return
			}

			log.Printf(
				"certificate job lease renewed job=%s expires=%s",
				grant.JobID,
				renewed.LeaseExpiresAt.UTC().
					Format(
						time.RFC3339,
					),
			)
		}
	}
}

func executeCertificateGrant(
	parent context.Context,
	client *agent.Client,
	agentToken string,
	ownerInstanceID string,
	baseDir string,
	grant model.CertificateJobGrant,
	refresh certificateRuntimeRefresher,
) {
	log.Printf(
		"certificate job started job=%s certificate=%s operation=%s domain=%s environment=%s",
		grant.JobID,
		grant.CertificateID,
		grant.Operation,
		grant.Domain,
		grant.Environment,
	)

	jobCtx, cancel :=
		context.WithCancel(
			parent,
		)

	defer cancel()

	go renewCertificateLease(
		jobCtx,
		client,
		agentToken,
		ownerInstanceID,
		grant,
		cancel,
	)

	report, err :=
		obtainCertificateWithRuntime(
			jobCtx,
			baseDir,
			grant,
			refresh,
		)

	if err != nil {
		report =
			model.CertificateJobResult{
				JobID:         grant.JobID,
				CertificateID: grant.CertificateID,
				LeaseToken:    grant.LeaseToken,
				Success:       false,
				ErrorMessage: safeCertificateError(
					err,
				),
			}
	}

	cancel()

	resultCtx, resultCancel :=
		context.WithTimeout(
			context.Background(),
			30*time.Second,
		)

	defer resultCancel()

	if resultErr :=
		client.CertificateJobResult(
			resultCtx,
			agentToken,
			report,
		); resultErr != nil {
		log.Printf(
			"certificate job result error job=%s: %v",
			grant.JobID,
			resultErr,
		)
		return
	}

	if err != nil {
		log.Printf(
			"certificate job failed job=%s certificate=%s: %v",
			grant.JobID,
			grant.CertificateID,
			err,
		)
		return
	}

	log.Printf(
		"certificate job completed job=%s certificate=%s",
		grant.JobID,
		grant.CertificateID,
	)
}

func runCertificateWorker(
	ctx context.Context,
	client *agent.Client,
	agentToken string,
	ownerInstanceID string,
	baseDir string,
	refresh certificateRuntimeRefresher,
) {
	log.Printf(
		"certificate worker started",
	)

	timer :=
		time.NewTimer(0)

	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-timer.C:
		}

		grant, exists, err :=
			client.CertificateJobClaim(
				ctx,
				agentToken,
				ownerInstanceID,
			)

		if err != nil {
			log.Printf(
				"certificate job claim error: %v",
				err,
			)
		} else if exists {
			if grant.JobID == "" ||
				grant.CertificateID == "" ||
				grant.LeaseToken == "" {
				log.Printf(
					"certificate job invalid grant",
				)
			} else {
				executeCertificateGrant(
					ctx,
					client,
					agentToken,
					ownerInstanceID,
					baseDir,
					grant,
					refresh,
				)
			}
		}

		select {
		case <-ctx.Done():
			return
		default:
			timer.Reset(
				certificateWorkerPollInterval,
			)
		}
	}
}

func validateCertificateWorkerConfig(
	agentToken string,
	ownerInstanceID string,
	baseDir string,
) error {
	if strings.TrimSpace(
		agentToken,
	) == "" {
		return fmt.Errorf(
			"certificate worker agent token missing",
		)
	}

	if strings.TrimSpace(
		ownerInstanceID,
	) == "" {
		return fmt.Errorf(
			"certificate worker owner instance id missing",
		)
	}

	if strings.TrimSpace(
		baseDir,
	) == "" {
		return fmt.Errorf(
			"certificate worker base directory missing",
		)
	}

	return nil
}
