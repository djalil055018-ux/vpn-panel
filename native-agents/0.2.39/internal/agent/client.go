package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"vpn-platform/internal/model"
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

type Registration struct {
	RuntimeCore string `json:"runtime_core,omitempty"`
	NodeID      string `json:"node_id"`
	TenantID    string `json:"tenant_id"`
	AgentToken  string `json:"agent_token"`
}

func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) Register(
	ctx context.Context,
	bootstrapToken string,
	agentVersion string,
	system SystemInfo,
) (Registration, error) {
	return c.RegisterForRuntime(ctx, bootstrapToken, agentVersion, system, "xray")
}

func (c *Client) RegisterForRuntime(ctx context.Context, bootstrapToken, agentVersion string, system SystemInfo, runtimeCore string) (Registration, error) {
	if !model.ValidRuntimeCore(runtimeCore) || (runtimeCore == "hysteria2" && !model.HysteriaAgentCompatible(agentVersion)) {
		return Registration{}, fmt.Errorf("unsupported runtime or incompatible agent release")
	}

	payload := map[string]string{
		"agent_version": agentVersion,
		"os_name":       system.OSName,
		"os_version":    system.OSVersion,
		"architecture":  system.Architecture,
	}
	if runtimeCore != "xray" {
		payload["runtime_core"] = runtimeCore
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return Registration{}, err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.BaseURL+"/api/v1/agent/register",
		bytes.NewReader(raw),
	)
	if err != nil {
		return Registration{}, err
	}

	req.Header.Set("Authorization", "Bearer "+bootstrapToken)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTP.Do(req)
	if err != nil {
		return Registration{}, err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)

		return Registration{}, fmt.Errorf(
			"registration failed: %s: %s",
			res.Status,
			string(body),
		)
	}

	var registration Registration

	if err := json.NewDecoder(res.Body).Decode(&registration); err != nil {
		return Registration{}, err
	}
	if registration.RuntimeCore != runtimeCore && (runtimeCore != "xray" || registration.RuntimeCore != "") {
		return Registration{}, fmt.Errorf("registration runtime differs from local selection")
	}

	return registration, nil
}

func (c *Client) DesiredState(
	ctx context.Context,
	agentToken string,
) (model.DesiredState, bool, error) {

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		c.BaseURL+"/api/v1/agent/desired-state",
		nil,
	)
	if err != nil {
		return model.DesiredState{}, false, err
	}

	req.Header.Set("Authorization", "Bearer "+agentToken)

	res, err := c.HTTP.Do(req)
	if err != nil {
		return model.DesiredState{}, false, err
	}

	defer res.Body.Close()

	if res.StatusCode == http.StatusNoContent {
		return model.DesiredState{}, false, nil
	}

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)

		return model.DesiredState{}, false, fmt.Errorf(
			"desired-state failed: %s: %s",
			res.Status,
			string(body),
		)
	}

	var state model.DesiredState

	if err := json.NewDecoder(res.Body).Decode(&state); err != nil {
		return model.DesiredState{}, false, err
	}

	return state, true, nil
}

func (c *Client) Health(
	ctx context.Context,
	agentToken string,
	report model.HealthReport,
) error {

	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.BaseURL+"/api/v1/agent/health",
		bytes.NewReader(raw),
	)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+agentToken)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(res.Body)

		return fmt.Errorf(
			"health failed: %s: %s",
			res.Status,
			string(body),
		)
	}

	return nil
}

func (c *Client) DeploymentStatus(
	ctx context.Context,
	agentToken string,
	report model.DeploymentReport,
) error {

	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.BaseURL+"/api/v1/agent/deployment-status",
		bytes.NewReader(raw),
	)
	if err != nil {
		return err
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+agentToken,
	)

	req.Header.Set(
		"Content-Type",
		"application/json",
	)

	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(res.Body)

		return fmt.Errorf(
			"deployment-status failed: %s: %s",
			res.Status,
			string(body),
		)
	}

	return nil
}

func (c *Client) Assignment(
	ctx context.Context,
	agentToken string,
) (
	model.AgentAssignment,
	bool,
	error,
) {
	req, err :=
		http.NewRequestWithContext(
			ctx,
			http.MethodGet,
			c.BaseURL+"/api/v1/agent/assignment",
			nil,
		)

	if err != nil {
		return model.AgentAssignment{},
			false,
			err
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+agentToken,
	)

	res, err :=
		c.HTTP.Do(req)

	if err != nil {
		return model.AgentAssignment{},
			false,
			err
	}

	defer res.Body.Close()

	if res.StatusCode ==
		http.StatusNoContent {

		return model.AgentAssignment{},
			false,
			nil
	}

	if res.StatusCode !=
		http.StatusOK {

		body, _ :=
			io.ReadAll(
				res.Body,
			)

		return model.AgentAssignment{},
			false,
			fmt.Errorf(
				"assignment failed: %s: %s",
				res.Status,
				string(body),
			)
	}

	var assignment model.AgentAssignment

	if err :=
		json.NewDecoder(
			res.Body,
		).Decode(
			&assignment,
		); err != nil {

		return model.AgentAssignment{},
			false,
			err
	}

	return assignment,
		true,
		nil
}

func (c *Client) RealityMaterial(
	ctx context.Context,
	agentToken string,
	material model.RealityPublicMaterial,
) error {
	raw, err :=
		json.Marshal(material)

	if err != nil {
		return err
	}

	req, err :=
		http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			c.BaseURL+
				"/api/v1/agent/reality-material",
			bytes.NewReader(raw),
		)

	if err != nil {
		return err
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+agentToken,
	)

	req.Header.Set(
		"Content-Type",
		"application/json",
	)

	res, err :=
		c.HTTP.Do(req)

	if err != nil {
		return err
	}

	defer res.Body.Close()

	if res.StatusCode !=
		http.StatusNoContent {

		body, _ :=
			io.ReadAll(
				res.Body,
			)

		return fmt.Errorf(
			"reality-material failed: %s: %s",
			res.Status,
			string(body),
		)
	}

	return nil
}

func (c *Client) CertificateJobClaim(
	ctx context.Context,
	agentToken string,
	ownerInstanceID string,
) (
	model.CertificateJobGrant,
	bool,
	error,
) {
	raw, err := json.Marshal(
		model.CertificateJobClaimRequest{
			OwnerInstanceID: ownerInstanceID,
		},
	)
	if err != nil {
		return model.CertificateJobGrant{}, false, err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.BaseURL+"/api/v1/agent/certificate-jobs/claim",
		bytes.NewReader(raw),
	)
	if err != nil {
		return model.CertificateJobGrant{}, false, err
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+agentToken,
	)
	req.Header.Set(
		"Content-Type",
		"application/json",
	)

	res, err := c.HTTP.Do(req)
	if err != nil {
		return model.CertificateJobGrant{}, false, err
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNoContent {
		return model.CertificateJobGrant{}, false, nil
	}

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)

		return model.CertificateJobGrant{},
			false,
			fmt.Errorf(
				"certificate-job claim failed: %s: %s",
				res.Status,
				string(body),
			)
	}

	var grant model.CertificateJobGrant

	if err := json.NewDecoder(
		res.Body,
	).Decode(
		&grant,
	); err != nil {
		return model.CertificateJobGrant{}, false, err
	}

	return grant, true, nil
}

func (c *Client) CertificateJobRenew(
	ctx context.Context,
	agentToken string,
	request model.CertificateJobLeaseRenewRequest,
) (
	model.CertificateJobLeaseGrant,
	error,
) {
	raw, err := json.Marshal(request)
	if err != nil {
		return model.CertificateJobLeaseGrant{}, err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.BaseURL+"/api/v1/agent/certificate-jobs/renew",
		bytes.NewReader(raw),
	)
	if err != nil {
		return model.CertificateJobLeaseGrant{}, err
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+agentToken,
	)
	req.Header.Set(
		"Content-Type",
		"application/json",
	)

	res, err := c.HTTP.Do(req)
	if err != nil {
		return model.CertificateJobLeaseGrant{}, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)

		return model.CertificateJobLeaseGrant{},
			fmt.Errorf(
				"certificate-job renew failed: %s: %s",
				res.Status,
				string(body),
			)
	}

	var grant model.CertificateJobLeaseGrant

	if err := json.NewDecoder(
		res.Body,
	).Decode(
		&grant,
	); err != nil {
		return model.CertificateJobLeaseGrant{}, err
	}

	return grant, nil
}

func (c *Client) CertificateJobResult(
	ctx context.Context,
	agentToken string,
	report model.CertificateJobResult,
) error {
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.BaseURL+"/api/v1/agent/certificate-jobs/result",
		bytes.NewReader(raw),
	)
	if err != nil {
		return err
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+agentToken,
	)
	req.Header.Set(
		"Content-Type",
		"application/json",
	)

	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(res.Body)

		return fmt.Errorf(
			"certificate-job result failed: %s: %s",
			res.Status,
			string(body),
		)
	}

	return nil
}

func (c *Client) NodeRebootJobClaim(
	ctx context.Context,
	agentToken string,
	ownerInstanceID string,
) (model.NodeRebootJobGrant, bool, error) {
	raw, err := json.Marshal(model.NodeRebootJobClaimRequest{OwnerInstanceID: ownerInstanceID})
	if err != nil {
		return model.NodeRebootJobGrant{}, false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/v1/agent/node-reboots/claim", bytes.NewReader(raw))
	if err != nil {
		return model.NodeRebootJobGrant{}, false, err
	}
	req.Header.Set("Authorization", "Bearer "+agentToken)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return model.NodeRebootJobGrant{}, false, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNoContent {
		return model.NodeRebootJobGrant{}, false, nil
	}
	if res.StatusCode != http.StatusOK {
		return model.NodeRebootJobGrant{}, false, fmt.Errorf("node reboot claim failed: %s", res.Status)
	}
	var grant model.NodeRebootJobGrant
	if err := json.NewDecoder(res.Body).Decode(&grant); err != nil {
		return model.NodeRebootJobGrant{}, false, err
	}
	return grant, true, nil
}

func (c *Client) NodeRebootJobResult(ctx context.Context, agentToken string, result model.NodeRebootJobResult) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/v1/agent/node-reboots/result", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+agentToken)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		return fmt.Errorf("node reboot result failed: %s", res.Status)
	}
	return nil
}
