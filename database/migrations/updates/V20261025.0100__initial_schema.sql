-- Initial platypus schema.
--
-- Platypus never stores parameter or secret values. Tables here hold users,
-- access policies, MFA credentials, sessions, a metadata cache of what exists
-- in AWS, notes and the audit trail.

-- Trigram indexes power the search box. pg_trgm is a trusted extension since
-- Postgres 13, so the database owner can create it without superuser rights.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ---------------------------------------------------------------------------
-- Application state: a single row.
-- ---------------------------------------------------------------------------
CREATE TABLE app_state (
    singleton           boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    bootstrapped        boolean NOT NULL DEFAULT false,
    policies_seeded     boolean NOT NULL DEFAULT false,
    blocked_at          timestamptz,
    blocked_by          text,
    sync_requested_at   timestamptz,
    sync_requested_by   text,
    sync_recheck_access boolean NOT NULL DEFAULT false
);

INSERT INTO app_state DEFAULT VALUES;

-- ---------------------------------------------------------------------------
-- Users, teams and policies.
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email               text NOT NULL UNIQUE CHECK (email <> '' AND email = lower(email)),
    is_admin            boolean NOT NULL DEFAULT false,
    -- Random WebAuthn user handle; must not reveal anything about the user.
    webauthn_handle     bytea NOT NULL UNIQUE,
    failed_mfa_attempts integer NOT NULL DEFAULT 0,
    locked_at           timestamptz,
    disabled_at         timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    -- Email of the admin who added the user ahead of time; NULL when the user
    -- was created on first login.
    created_by          text,
    first_login_at      timestamptz,
    last_seen_at        timestamptz
);

CREATE TABLE teams (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        text NOT NULL UNIQUE CHECK (name <> ''),
    description text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE team_members (
    team_id  bigint NOT NULL REFERENCES teams (id) ON DELETE CASCADE,
    user_id  bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    added_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, user_id)
);

CREATE INDEX team_members_user_id_idx ON team_members (user_id);

CREATE TABLE policies (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        text NOT NULL UNIQUE CHECK (name <> ''),
    description text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- A rule grants permissions on parameters or secrets whose name matches the
-- pattern: an exact name, or a prefix ending in '*'.
CREATE TABLE policy_rules (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    policy_id  bigint NOT NULL REFERENCES policies (id) ON DELETE CASCADE,
    kind       text NOT NULL CHECK (kind IN ('ssm', 'secret')),
    pattern    text NOT NULL CHECK (pattern <> ''),
    can_list   boolean NOT NULL DEFAULT false,
    can_create boolean NOT NULL DEFAULT false,
    can_edit   boolean NOT NULL DEFAULT false,
    can_reveal boolean NOT NULL DEFAULT false,
    position   integer NOT NULL DEFAULT 0
);

CREATE INDEX policy_rules_policy_id_idx ON policy_rules (policy_id);

CREATE TABLE user_policies (
    user_id   bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    policy_id bigint NOT NULL REFERENCES policies (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, policy_id)
);

CREATE INDEX user_policies_policy_id_idx ON user_policies (policy_id);

CREATE TABLE team_policies (
    team_id   bigint NOT NULL REFERENCES teams (id) ON DELETE CASCADE,
    policy_id bigint NOT NULL REFERENCES policies (id) ON DELETE CASCADE,
    PRIMARY KEY (team_id, policy_id)
);

CREATE INDEX team_policies_policy_id_idx ON team_policies (policy_id);

-- ---------------------------------------------------------------------------
-- Second factors for admin mode.
-- ---------------------------------------------------------------------------
CREATE TABLE totp_credentials (
    user_id           bigint PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    -- AES-256-GCM ciphertext of the TOTP secret, see PLATYPUS_ENCRYPTION_KEY.
    secret_ciphertext bytea NOT NULL,
    key_id            text NOT NULL,
    -- Highest 30-second time step accepted so far; blocks code reuse.
    last_used_step    bigint NOT NULL DEFAULT 0,
    -- NULL while the user hasn't confirmed enrollment with a first code.
    confirmed_at      timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE passkeys (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id       bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id bytea NOT NULL UNIQUE,
    -- The WebAuthn credential: public key, sign counter and flags. No secrets.
    credential    jsonb NOT NULL,
    name          text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz
);

CREATE INDEX passkeys_user_id_idx ON passkeys (user_id);

CREATE TABLE recovery_codes (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash  text NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX recovery_codes_user_id_idx ON recovery_codes (user_id);

-- ---------------------------------------------------------------------------
-- Bootstrap tokens, sessions and rate limits.
-- ---------------------------------------------------------------------------
CREATE TABLE bootstrap_tokens (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token_hash text NOT NULL,
    issued_by  text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    used_by    bigint REFERENCES users (id),
    revoked_at timestamptz
);

CREATE TABLE sessions (
    -- SHA-256 of the cookie value; the cookie value itself is never stored.
    id_hash                    bytea PRIMARY KEY,
    user_id                    bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf_token                 text NOT NULL,
    created_at                 timestamptz NOT NULL DEFAULT now(),
    last_seen_at               timestamptz NOT NULL DEFAULT now(),
    expires_at                 timestamptz NOT NULL,
    admin_mode_until           timestamptz,
    -- Set once the user entered a valid bootstrap token, until bootstrap completes.
    bootstrap_token_id         bigint REFERENCES bootstrap_tokens (id),
    -- State of a passkey registration or login that is in progress.
    webauthn_ceremony          jsonb,
    webauthn_ceremony_until    timestamptz
);

CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

CREATE TABLE rate_limit_counters (
    key          text NOT NULL,
    window_start timestamptz NOT NULL,
    count        integer NOT NULL,
    PRIMARY KEY (key, window_start)
);

CREATE INDEX rate_limit_counters_window_start_idx ON rate_limit_counters (window_start);

-- ---------------------------------------------------------------------------
-- Metadata cache of SSM parameters and Secrets Manager secrets. Never values.
-- ---------------------------------------------------------------------------
CREATE TABLE items (
    kind               text NOT NULL CHECK (kind IN ('ssm', 'secret')),
    name               text NOT NULL,
    description        text NOT NULL DEFAULT '',
    kms_key_id         text NOT NULL DEFAULT '',
    last_modified_at   timestamptz,
    -- Changes whenever the item changes in AWS (SSM version, secret version
    -- and change date). A change resets the access check below.
    change_marker      text NOT NULL,
    -- SSM only.
    ssm_type           text NOT NULL DEFAULT '',
    ssm_tier           text NOT NULL DEFAULT '',
    ssm_data_type      text NOT NULL DEFAULT '',
    ssm_version        bigint NOT NULL DEFAULT 0,
    -- Secrets Manager only.
    secret_arn         text NOT NULL DEFAULT '',
    secret_version_id  text NOT NULL DEFAULT '',
    rotation_enabled   boolean NOT NULL DEFAULT false,
    -- Tags; NULL until fetched (SSM lists don't include tags).
    tags               jsonb,
    -- Whether platypus itself can access the item. Only 'ok' items are shown.
    access             text NOT NULL DEFAULT 'unknown' CHECK (access IN ('unknown', 'ok', 'denied')),
    access_checked_at  timestamptz,
    synced_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, name)
);

CREATE INDEX items_name_prefix_idx ON items (kind, name text_pattern_ops);
CREATE INDEX items_name_trgm_idx ON items USING gin (name gin_trgm_ops);
CREATE INDEX items_description_trgm_idx ON items USING gin (description gin_trgm_ops);
CREATE INDEX items_access_idx ON items (access) WHERE access <> 'ok';

-- Notes live only here and are never sent to AWS. They are kept when the item
-- disappears from AWS, so there is deliberately no foreign key to items.
CREATE TABLE notes (
    kind       text NOT NULL CHECK (kind IN ('ssm', 'secret')),
    name       text NOT NULL,
    body       text NOT NULL CHECK (body <> '' AND char_length(body) <= 2000),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by text NOT NULL,
    PRIMARY KEY (kind, name)
);

CREATE INDEX notes_body_trgm_idx ON notes USING gin (body gin_trgm_ops);

CREATE TABLE sync_runs (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    trigger           text NOT NULL CHECK (trigger IN ('schedule', 'manual')),
    recheck_access    boolean NOT NULL DEFAULT false,
    started_at        timestamptz NOT NULL DEFAULT now(),
    finished_at       timestamptz,
    status            text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'succeeded', 'failed')),
    parameters_seen   integer NOT NULL DEFAULT 0,
    secrets_seen      integer NOT NULL DEFAULT 0,
    access_checked    integer NOT NULL DEFAULT 0,
    message           text NOT NULL DEFAULT ''
);

CREATE INDEX sync_runs_started_at_idx ON sync_runs (started_at);

-- ---------------------------------------------------------------------------
-- Audit trail. The application role may insert and delete (prune) rows, but
-- never update them; see afterMigrate.sql.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_events (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at   timestamptz NOT NULL DEFAULT now(),
    -- No foreign key: the audit trail must not depend on other tables.
    actor_id      bigint,
    actor_email   text NOT NULL DEFAULT '',
    action        text NOT NULL,
    outcome       text NOT NULL CHECK (outcome IN ('allowed', 'denied', 'error')),
    resource_kind text NOT NULL DEFAULT '',
    resource_name text NOT NULL DEFAULT '',
    reason        text NOT NULL DEFAULT '',
    client_ip     text NOT NULL DEFAULT '',
    user_agent    text NOT NULL DEFAULT '',
    request_id    text NOT NULL DEFAULT '',
    details       jsonb NOT NULL DEFAULT '{}'
);

CREATE INDEX audit_events_occurred_at_idx ON audit_events (occurred_at);
CREATE INDEX audit_events_actor_email_idx ON audit_events (actor_email, occurred_at);
CREATE INDEX audit_events_resource_name_idx ON audit_events (resource_name, occurred_at);
CREATE INDEX audit_events_action_idx ON audit_events (action, occurred_at);
