"use client";

import {
  useActionState,
} from "react";

import {
  createRecoveryAction,
  createRolloutAction,
  evaluateCoreUpdateAction,
  evaluateRecoveryAction,
  mutateRecoveryAction,
  mutateRolloutAction,
  type ControlActionState,
} from "@/app/control-actions";

import type {
  CoreRelease,
} from "@/lib/control-plane";

import {
  ru,
} from "@/lib/i18n/ru";

const initialState:
  ControlActionState = {
    ok: true,
    title: "",
    message: "",
  };

function Result({
  state,
}: {
  state:
    ControlActionState;
}) {
  if (!state.title) {
    return null;
  }

  return (
    <div
      className={
        state.ok
          ? "action-result success-result"
          : "action-result error-result"
      }
    >
      <strong>
        {state.title}
      </strong>

      <p>
        {state.message}
      </p>

      {state.data !==
        undefined && (
        <details>
          <summary>
            {ru.control.technicalData}
          </summary>

          <pre>
            {JSON.stringify(
              state.data,
              null,
              2
            )}
          </pre>
        </details>
      )}
    </div>
  );
}

function idFromResult(
  value: unknown
): string {
  if (
    !value ||
    typeof value !==
      "object"
  ) {
    return "";
  }

  const id =
    (
      value as {
        id?: unknown;
      }
    ).id;

  return typeof id ===
    "string"
    ? id
    : "";
}

export function ControlCenter({
  nodeID,
  currentVersion,
  latestGeneration,
  releases,
  coreUpdateStatus,
}: {
  nodeID: string;
  currentVersion: string;
  latestGeneration: number;
  releases: CoreRelease[];
  coreUpdateStatus:
    Record<string, unknown>;
}) {
  const [
    evaluationState,
    evaluationAction,
    evaluationPending,
  ] = useActionState(
    evaluateCoreUpdateAction,
    initialState
  );

  const [
    rolloutCreateState,
    rolloutCreateAction,
    rolloutCreatePending,
  ] = useActionState(
    createRolloutAction,
    initialState
  );

  const [
    rolloutMutationState,
    rolloutMutationAction,
    rolloutMutationPending,
  ] = useActionState(
    mutateRolloutAction,
    initialState
  );

  const [
    recoveryEvaluationState,
    recoveryEvaluationAction,
    recoveryEvaluationPending,
  ] = useActionState(
    evaluateRecoveryAction,
    initialState
  );

  const [
    recoveryCreateState,
    recoveryCreateAction,
    recoveryCreatePending,
  ] = useActionState(
    createRecoveryAction,
    initialState
  );

  const [
    recoveryMutationState,
    recoveryMutationAction,
    recoveryMutationPending,
  ] = useActionState(
    mutateRecoveryAction,
    initialState
  );

  const rolloutPlanID =
    idFromResult(
      rolloutMutationState.data
    ) ||
    idFromResult(
      rolloutCreateState.data
    );

  const recoveryAttemptID =
    idFromResult(
      recoveryMutationState.data
    ) ||
    idFromResult(
      recoveryCreateState.data
    );

  return (
    <div className="control-stack">
      <section className="control-card">
        <div className="control-card-header">
          <div>
            <span className="control-index">
              01
            </span>

            <h2>
              {ru.control.coreEvaluation}
            </h2>

            <p>
              {ru.control
                .coreEvaluationSubtitle}
            </p>
          </div>

          <span className="control-badge">
            {ru.control.safe}
          </span>
        </div>

        <div className="current-line">
          {ru.control.currentXray}:
          <strong>
            {currentVersion ||
              ru.common.unknown}
          </strong>
        </div>

        <form
          action={evaluationAction}
          className="control-form"
        >
          <input
            type="hidden"
            name="node_id"
            value={nodeID}
          />

          <label>
            {ru.control.targetRelease}

            <select
              name="version"
              required
              defaultValue=""
            >
              <option
                value=""
                disabled
              >
                {ru.control.selectVersion}
              </option>

              {releases.map(
                (
                  release,
                  index
                ) => (
                  <option
                    key={
                      release.id ??
                      `${release.version}-${index}`
                    }
                    value={
                      release.version
                    }
                  >
                    {release.version}
                    {" · "}
                    {release.channel ??
                      ru.common.unknown}
                  </option>
                )
              )}
            </select>
          </label>

          <button
            className="button primary"
            disabled={
              evaluationPending
            }
          >
            {evaluationPending
              ? ru.control.evaluating
              : ru.control.checkUpdate}
          </button>
        </form>

        <Result
          state={evaluationState}
        />

        <details className="json-details">
          <summary>
            {ru.control.currentPolicy}
          </summary>

          <pre>
            {JSON.stringify(
              coreUpdateStatus,
              null,
              2
            )}
          </pre>
        </details>
      </section>

      <section className="control-card">
        <div className="control-card-header">
          <div>
            <span className="control-index">
              02
            </span>

            <h2>
              {ru.control.rolloutPlanner}
            </h2>

            <p>
              {ru.control.rolloutSubtitle}
            </p>
          </div>

          <span className="control-badge warning">
            {ru.control.mutation}
          </span>
        </div>

        <form
          action={
            rolloutCreateAction
          }
          className="control-form"
        >
          <input
            type="hidden"
            name="node_id"
            value={nodeID}
          />

          <button
            className="button"
            disabled={
              rolloutCreatePending
            }
          >
            {rolloutCreatePending
              ? ru.control.creating
              : ru.control
                  .createRolloutPlan}
          </button>
        </form>

        <Result
          state={
            rolloutCreateState
          }
        />

        {rolloutPlanID && (
          <div className="mutation-box">
            <div>
              <span>
                {ru.control.activePlan}
              </span>

              <strong className="mono">
                {rolloutPlanID}
              </strong>
            </div>

            <form
              action={
                rolloutMutationAction
              }
              className="inline-actions"
            >
              <input
                type="hidden"
                name="node_id"
                value={nodeID}
              />

              <input
                type="hidden"
                name="plan_id"
                value={
                  rolloutPlanID
                }
              />

              <button
                name="operation"
                value="approve"
                className="button"
                disabled={
                  rolloutMutationPending
                }
              >
                {ru.control.approvePlan}
              </button>

              <button
                name="operation"
                value="cancel"
                className="button ghost"
                disabled={
                  rolloutMutationPending
                }
              >
                {ru.common.cancel}
              </button>
            </form>

            <form
              action={
                rolloutMutationAction
              }
              className="execute-form"
            >
              <input
                type="hidden"
                name="node_id"
                value={nodeID}
              />

              <input
                type="hidden"
                name="plan_id"
                value={
                  rolloutPlanID
                }
              />

              <input
                type="hidden"
                name="operation"
                value="execute"
              />

              <label>
                {ru.control.executeHint}

                <input
                  name="confirmation"
                  placeholder="EXECUTE"
                  autoComplete="off"
                />
              </label>

              <button
                className="button danger"
                disabled={
                  rolloutMutationPending
                }
              >
                {ru.control.executeRollout}
              </button>
            </form>
          </div>
        )}

        <Result
          state={
            rolloutMutationState
          }
        />
      </section>

      <section className="control-card">
        <div className="control-card-header">
          <div>
            <span className="control-index">
              03
            </span>

            <h2>
              {ru.control.recoveryEngine}
            </h2>

            <p>
              {ru.control.recoverySubtitle}
            </p>
          </div>

          <span className="control-badge danger">
            {ru.control.recoveryBadge}
          </span>
        </div>

        <div className="current-line">
          {ru.control.latestGeneration}:
          <strong>
            {latestGeneration ||
              ru.common.unknown}
          </strong>
        </div>

        {latestGeneration >
          0 && (
          <>
            <form
              action={
                recoveryEvaluationAction
              }
              className="control-form"
            >
              <input
                type="hidden"
                name="node_id"
                value={nodeID}
              />

              <input
                type="hidden"
                name="generation"
                value={
                  latestGeneration
                }
              />

              <button
                className="button primary"
                disabled={
                  recoveryEvaluationPending
                }
              >
                {recoveryEvaluationPending
                  ? ru.control.evaluating
                  : ru.control
                      .evaluateRecovery}
              </button>
            </form>

            <Result
              state={
                recoveryEvaluationState
              }
            />

            <form
              action={
                recoveryCreateAction
              }
              className="control-form"
            >
              <input
                type="hidden"
                name="node_id"
                value={nodeID}
              />

              <input
                type="hidden"
                name="generation"
                value={
                  latestGeneration
                }
              />

              <button
                className="button"
                disabled={
                  recoveryCreatePending
                }
              >
                {recoveryCreatePending
                  ? ru.control.creating
                  : ru.control
                      .createRecoveryAttempt}
              </button>
            </form>
          </>
        )}

        <Result
          state={
            recoveryCreateState
          }
        />

        {recoveryAttemptID && (
          <div className="mutation-box">
            <div>
              <span>
                {ru.control.recoveryAttempt}
              </span>

              <strong className="mono">
                {recoveryAttemptID}
              </strong>
            </div>

            <form
              action={
                recoveryMutationAction
              }
              className="inline-actions"
            >
              <input
                type="hidden"
                name="node_id"
                value={nodeID}
              />

              <input
                type="hidden"
                name="attempt_id"
                value={
                  recoveryAttemptID
                }
              />

              <button
                name="operation"
                value="approve"
                className="button"
                disabled={
                  recoveryMutationPending
                }
              >
                {ru.control.approveRecovery}
              </button>

              <button
                name="operation"
                value="cancel"
                className="button ghost"
                disabled={
                  recoveryMutationPending
                }
              >
                {ru.common.cancel}
              </button>
            </form>

            <form
              action={
                recoveryMutationAction
              }
              className="execute-form"
            >
              <input
                type="hidden"
                name="node_id"
                value={nodeID}
              />

              <input
                type="hidden"
                name="attempt_id"
                value={
                  recoveryAttemptID
                }
              />

              <input
                type="hidden"
                name="operation"
                value="execute"
              />

              <label>
                {ru.control
                  .recoveryExecuteHint}

                <input
                  name="confirmation"
                  placeholder="EXECUTE"
                  autoComplete="off"
                />
              </label>

              <button
                className="button danger"
                disabled={
                  recoveryMutationPending
                }
              >
                {ru.control.executeRecovery}
              </button>
            </form>
          </div>
        )}

        <Result
          state={
            recoveryMutationState
          }
        />
      </section>

      <section className="control-card">
        <div className="control-card-header">
          <div>
            <span className="control-index">
              04
            </span>

            <h2>
              {ru.control.advancedSafety}
            </h2>

            <p>
              {ru.control
                .advancedSafetySubtitle}
            </p>
          </div>

          <span className="control-badge danger">
            {ru.control.locked}
          </span>
        </div>

        <div className="safety-note">
          {ru.control.lockedMessage}
        </div>
      </section>
    </div>
  );
}
