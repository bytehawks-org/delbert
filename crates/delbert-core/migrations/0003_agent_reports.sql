-- Latest compliance report received from each agent over the message bus.

CREATE TABLE agent_reports (
    agent_id    uuid PRIMARY KEY REFERENCES agents (id) ON DELETE CASCADE,
    received_at timestamptz NOT NULL DEFAULT now(),
    version     bigint,
    compliant   boolean NOT NULL,
    report      jsonb NOT NULL
);
