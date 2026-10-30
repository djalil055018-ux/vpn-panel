CREATE INDEX IF NOT EXISTS
    deployments_nonterminal_updated_idx
ON deployments(
    updated_at ASC,
    id
)
WHERE status IN (
    'pending',
    'applying'
);

CREATE UNIQUE INDEX IF NOT EXISTS
    audit_events_stuck_episode_unique_idx
ON audit_events(
    (payload->>'episode_key')
)
WHERE event_type = 'deployment.stuck_detected'
  AND payload ? 'episode_key';
