-- Passkey ceremonies move out of the session row into their own table, so a
-- finish can take one with a single DELETE ... RETURNING: exactly one request
-- can consume a started ceremony, even under concurrency.
CREATE TABLE webauthn_ceremonies (
    id_hash         bytea PRIMARY KEY REFERENCES sessions (id_hash) ON DELETE CASCADE,
    ceremony        jsonb NOT NULL,
    ceremony_until  timestamptz NOT NULL
);

INSERT INTO webauthn_ceremonies (id_hash, ceremony, ceremony_until)
SELECT id_hash, webauthn_ceremony, webauthn_ceremony_until
FROM sessions
WHERE webauthn_ceremony IS NOT NULL AND webauthn_ceremony_until IS NOT NULL;
