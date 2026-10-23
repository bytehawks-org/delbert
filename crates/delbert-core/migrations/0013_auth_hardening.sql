-- Authentication hardening: MFA (TOTP + recovery codes), login throttling, richer sessions.

ALTER TABLE users
    ADD COLUMN totp_secret    bytea,                          -- sealed with the Core key; set while enrolling
    ADD COLUMN totp_enabled   boolean NOT NULL DEFAULT false, -- true once the first code was confirmed
    ADD COLUMN totp_last_step bigint  NOT NULL DEFAULT 0,     -- replay protection: a step is accepted once
    ADD COLUMN must_change_password boolean NOT NULL DEFAULT false;

CREATE TABLE user_recovery_codes (
    user_id   uuid  NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash bytea NOT NULL,
    PRIMARY KEY (user_id, code_hash)
);

-- Sessions: listable/revocable, idle timeout, optional CSRF secret (cookie sessions),
-- and a pending state until the second factor is given.
ALTER TABLE sessions
    ADD COLUMN id         uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    ADD COLUMN last_seen  timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN csrf_hash  bytea,
    ADD COLUMN mfa_ok     boolean NOT NULL DEFAULT true,
    ADD COLUMN ip         text,
    ADD COLUMN user_agent text;

-- Every login attempt; the throttle counts recent failures per username and per address.
CREATE TABLE login_attempts (
    id       bigserial PRIMARY KEY,
    at       timestamptz NOT NULL DEFAULT now(),
    username text NOT NULL,
    ip       text NOT NULL,
    success  boolean NOT NULL
);
CREATE INDEX login_attempts_user_idx ON login_attempts (username, at);
CREATE INDEX login_attempts_ip_idx ON login_attempts (ip, at);
