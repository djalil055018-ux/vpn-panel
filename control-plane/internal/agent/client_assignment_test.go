package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"vpn-platform/internal/model"
)

func TestAssignment(
	t *testing.T,
) {
	server :=
		httptest.NewServer(
			http.HandlerFunc(
				func(
					w http.ResponseWriter,
					r *http.Request,
				) {
					if r.URL.Path !=
						"/api/v1/agent/assignment" {

						t.Fatalf(
							"path=%s",
							r.URL.Path,
						)
					}

					if got :=
						r.Header.Get(
							"Authorization",
						); got !=
						"Bearer test-token" {

						t.Fatalf(
							"authorization=%q",
							got,
						)
					}

					w.Header().
						Set(
							"Content-Type",
							"application/json",
						)

					_, _ =
						w.Write(
							[]byte(`{
								"desired_state": {
									"generation": 15,
									"core": {
										"type": "xray",
										"version": "26.7.28",
										"download_url": "",
										"sha256": ""
									},
									"services": []
								},
								"execution": {
									"deployment_id": "deployment-a",
									"generation": 15,
									"execution_id": "execution-a",
									"execution_epoch": 15
								},
								"deployment_status": "healthy",
								"node_applied_generation": 15,
								"applied_core_version": "26.7.28"
							}`),
						)
				},
			),
		)

	defer server.Close()

	client :=
		NewClient(
			server.URL,
		)

	assignment, exists, err :=
		client.Assignment(
			context.Background(),
			"test-token",
		)

	if err != nil {
		t.Fatal(err)
	}

	if !exists {
		t.Fatal(
			"assignment does not exist",
		)
	}

	if assignment.DesiredState.Generation !=
		15 {

		t.Fatalf(
			"desired generation=%d",
			assignment.DesiredState.Generation,
		)
	}

	if assignment.Execution.Generation !=
		15 {

		t.Fatalf(
			"execution generation=%d",
			assignment.Execution.Generation,
		)
	}

	if assignment.Execution.ExecutionID !=
		"execution-a" {

		t.Fatalf(
			"execution id=%q",
			assignment.Execution.ExecutionID,
		)
	}

	if assignment.Execution.ExecutionEpoch !=
		15 {

		t.Fatalf(
			"execution epoch=%d",
			assignment.Execution.ExecutionEpoch,
		)
	}

	if assignment.DeploymentStatus !=
		"healthy" {

		t.Fatalf(
			"deployment status=%q",
			assignment.DeploymentStatus,
		)
	}

	if assignment.NodeAppliedGeneration !=
		15 {

		t.Fatalf(
			"node applied generation=%d",
			assignment.NodeAppliedGeneration,
		)
	}

	if assignment.AppliedCoreVersion !=
		"26.7.28" {

		t.Fatalf(
			"applied core version=%q",
			assignment.AppliedCoreVersion,
		)
	}
}

func TestAssignmentNoContent(
	t *testing.T,
) {
	server :=
		httptest.NewServer(
			http.HandlerFunc(
				func(
					w http.ResponseWriter,
					_ *http.Request,
				) {
					w.WriteHeader(
						http.StatusNoContent,
					)
				},
			),
		)

	defer server.Close()

	client :=
		NewClient(
			server.URL,
		)

	assignment, exists, err :=
		client.Assignment(
			context.Background(),
			"test-token",
		)

	if err != nil {
		t.Fatal(err)
	}

	if exists {
		t.Fatalf(
			"unexpected assignment: %+v",
			assignment,
		)
	}
}

var _ = model.AgentAssignment{}
