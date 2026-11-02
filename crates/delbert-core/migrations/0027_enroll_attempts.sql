-- Failed enrollments, for the per-address throttle of the unauthenticated enrollment endpoints
-- (agents and proxies) and to bound how much of them reaches the audit trail.
CREATE TABLE enroll_attempts (
    id   bigserial PRIMARY KEY,
    at   timestamptz NOT NULL DEFAULT now(),
    -- Client address, or `proxy:<site>` for agents enrolling through a proxy.
    key  text NOT NULL,
    -- `failure`: a rejected key; `throttled`: the first refused request of a blocked key.
    kind text NOT NULL CHECK (kind IN ('failure', 'throttled'))
);
CREATE INDEX enroll_attempts_key_idx ON enroll_attempts (key, at);
