-- Per-action audit events sent by agents (docs/ABSTRACT.md §6). Delivery is at least once (agent
-- spool, proxy queue), so every event carries an id chosen by the agent; a second delivery of the
-- same id is dropped here. The ids also bound how many events one agent may add to the trail per hour.
CREATE TABLE agent_event_ids (
    agent_id    uuid NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    event_id    text NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, event_id)
);
CREATE INDEX agent_event_ids_recent ON agent_event_ids (agent_id, received_at);
