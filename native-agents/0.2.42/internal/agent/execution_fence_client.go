package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"vpn-platform/internal/model"
)

func (c *Client) AcknowledgeExecutionFence(
	ctx context.Context,
	agentToken string,
	request model.ExecutionFenceAckRequest,
) (
	model.ExecutionFenceRequest,
	error,
) {
	raw, err :=
		json.Marshal(
			request,
		)

	if err != nil {
		return model.ExecutionFenceRequest{},
			err
	}

	req, err :=
		http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			c.BaseURL+
				"/api/v1/agent/execution/fence-ack",
			bytes.NewReader(raw),
		)

	if err != nil {
		return model.ExecutionFenceRequest{},
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
		return model.ExecutionFenceRequest{},
			err
	}

	defer res.Body.Close()

	if res.StatusCode !=
		http.StatusOK {

		return model.ExecutionFenceRequest{},
			responseError(
				"execution fence acknowledgement",
				res,
			)
	}

	var acknowledged model.ExecutionFenceRequest

	if err :=
		json.NewDecoder(
			res.Body,
		).Decode(
			&acknowledged,
		); err != nil {

		return model.ExecutionFenceRequest{},
			err
	}

	if acknowledged.ID == "" {
		return model.ExecutionFenceRequest{},
			fmt.Errorf(
				"execution fence acknowledgement returned empty request id",
			)
	}

	if acknowledged.State !=
		"acknowledged" {

		return model.ExecutionFenceRequest{},
			fmt.Errorf(
				"execution fence acknowledgement returned state %q",
				acknowledged.State,
			)
	}

	return acknowledged,
		nil
}
