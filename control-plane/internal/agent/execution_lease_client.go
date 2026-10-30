package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"vpn-platform/internal/model"
)

type HTTPStatusError struct {
	Operation  string
	StatusCode int
	Status     string
	Body       string
}

func (e *HTTPStatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf(
			"%s failed: %s",
			e.Operation,
			e.Status,
		)
	}

	return fmt.Sprintf(
		"%s failed: %s: %s",
		e.Operation,
		e.Status,
		e.Body,
	)
}

func HTTPErrorStatus(
	err error,
) (
	int,
	bool,
) {
	var statusErr *HTTPStatusError

	if !errors.As(
		err,
		&statusErr,
	) {
		return 0,
			false
	}

	return statusErr.StatusCode,
		true
}

func responseError(
	operation string,
	res *http.Response,
) error {
	body, _ :=
		io.ReadAll(
			io.LimitReader(
				res.Body,
				4096,
			),
		)

	return &HTTPStatusError{
		Operation: operation,

		StatusCode: res.StatusCode,

		Status: res.Status,

		Body: strings.TrimSpace(
			string(body),
		),
	}
}

func (c *Client) ClaimExecutionLease(
	ctx context.Context,
	agentToken string,
	request model.ExecutionLeaseClaimRequest,
) (
	model.ExecutionLeaseGrant,
	error,
) {
	raw, err :=
		json.Marshal(
			request,
		)

	if err != nil {
		return model.ExecutionLeaseGrant{},
			err
	}

	req, err :=
		http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			c.BaseURL+
				"/api/v1/agent/execution/claim",
			bytes.NewReader(raw),
		)

	if err != nil {
		return model.ExecutionLeaseGrant{},
			err
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
		return model.ExecutionLeaseGrant{},
			err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return model.ExecutionLeaseGrant{},
			responseError(
				"execution lease claim",
				res,
			)
	}

	var grant model.ExecutionLeaseGrant

	if err :=
		json.NewDecoder(
			res.Body,
		).Decode(
			&grant,
		); err != nil {

		return model.ExecutionLeaseGrant{},
			err
	}

	if grant.LeaseToken == "" {
		return model.ExecutionLeaseGrant{},
			fmt.Errorf(
				"execution lease claim returned empty lease token",
			)
	}

	if grant.LeaseExpiresAt.IsZero() {
		return model.ExecutionLeaseGrant{},
			fmt.Errorf(
				"execution lease claim returned empty expiry",
			)
	}

	if grant.RenewAfterSeconds < 1 {
		return model.ExecutionLeaseGrant{},
			fmt.Errorf(
				"execution lease claim returned invalid renew interval",
			)
	}

	return grant,
		nil
}

func (c *Client) RenewExecutionLease(
	ctx context.Context,
	agentToken string,
	request model.ExecutionLeaseRenewRequest,
) (
	model.ExecutionLeaseGrant,
	error,
) {
	raw, err :=
		json.Marshal(
			request,
		)

	if err != nil {
		return model.ExecutionLeaseGrant{},
			err
	}

	req, err :=
		http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			c.BaseURL+
				"/api/v1/agent/execution/renew",
			bytes.NewReader(raw),
		)

	if err != nil {
		return model.ExecutionLeaseGrant{},
			err
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
		return model.ExecutionLeaseGrant{},
			err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return model.ExecutionLeaseGrant{},
			responseError(
				"execution lease renew",
				res,
			)
	}

	var grant model.ExecutionLeaseGrant

	if err :=
		json.NewDecoder(
			res.Body,
		).Decode(
			&grant,
		); err != nil {

		return model.ExecutionLeaseGrant{},
			err
	}

	if grant.LeaseExpiresAt.IsZero() {
		return model.ExecutionLeaseGrant{},
			fmt.Errorf(
				"execution lease renew returned empty expiry",
			)
	}

	if grant.RenewAfterSeconds < 1 {
		return model.ExecutionLeaseGrant{},
			fmt.Errorf(
				"execution lease renew returned invalid renew interval",
			)
	}

	return grant,
		nil
}
