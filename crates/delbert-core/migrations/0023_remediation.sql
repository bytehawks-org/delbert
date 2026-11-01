-- Remediation (docs/REMEDIATION.md): an operator's decision to apply a version again after the
-- agent rolled it back. The Core signs it into the agent's effective policy until the agent
-- reports that the quarantine is gone.

ALTER TABLE agents
    ADD COLUMN force_version bigint,
    ADD COLUMN force_id      text,
    ADD COLUMN forced_by     text,
    ADD COLUMN forced_at     timestamptz;

-- Forcing is a decision about a host that failed: tenant administrators, not every operator.
UPDATE roles SET permissions = array_append(permissions, 'agents:remediate')
 WHERE name = 'tenant-admin' AND NOT ('agents:remediate' = ANY (permissions));
