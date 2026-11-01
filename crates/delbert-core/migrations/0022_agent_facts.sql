-- Host facts reported by the agent: a small informational subset (OS family, distribution, version,
-- kernel, hostname, domain, addresses). Overwritten at each report that carries them, never audited,
-- never used for authorization; removed with the agent. Delbert is not a CMDB.

ALTER TABLE agent_reports
    ADD COLUMN facts    jsonb,
    ADD COLUMN facts_at timestamptz;
