ALTER TABLE recovery_attempts
DROP CONSTRAINT IF EXISTS recovery_attempts_active_source_status_chk;

ALTER TABLE recovery_attempts
ADD CONSTRAINT recovery_attempts_active_source_status_chk
CHECK (
	status <> ALL (
		ARRAY[
			'planned'::text,
			'approved'::text,
			'executed'::text
		]
	)
	OR
	source_deployment_status = ANY (
		ARRAY[
			'rolled_back'::text,
			'pending'::text,
			'applying'::text
		]
	)
);
