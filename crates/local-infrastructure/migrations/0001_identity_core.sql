CREATE TABLE credential_references (
    id TEXT PRIMARY KEY
        CHECK(length(id) = 36 AND substr(id, 9, 1) = '-' AND substr(id, 14, 1) = '-'
            AND substr(id, 19, 1) = '-' AND substr(id, 24, 1) = '-'
            AND id NOT GLOB '*[^0-9a-f-]*'),
    kind TEXT NOT NULL CHECK(kind IN ('api_key', 'oauth_bundle')),
    auth_mode TEXT GENERATED ALWAYS AS (
        CASE kind
            WHEN 'api_key' THEN 'api_key'
            WHEN 'oauth_bundle' THEN 'oauth'
        END
    ) STORED,
    platform_backend TEXT NOT NULL CHECK(platform_backend = 'windows_dpapi_current_user'),
    schema_fingerprint TEXT NOT NULL
        CHECK(length(schema_fingerprint) = 64 AND schema_fingerprint NOT GLOB '*[^0-9a-f]*'),
    credential_fingerprint TEXT NOT NULL
        CHECK(length(credential_fingerprint) = 64 AND credential_fingerprint NOT GLOB '*[^0-9a-f]*'),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= created_at_unix_ms),
    version INTEGER NOT NULL CHECK(version >= 1),
    UNIQUE(id, auth_mode)
) STRICT;

CREATE TABLE runtime_identities (
    id TEXT PRIMARY KEY
        CHECK(length(id) = 36 AND substr(id, 9, 1) = '-' AND substr(id, 14, 1) = '-'
            AND substr(id, 19, 1) = '-' AND substr(id, 24, 1) = '-'
            AND id NOT GLOB '*[^0-9a-f-]*'),
    name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 80),
    provider_id TEXT NOT NULL CHECK(length(provider_id) BETWEEN 1 AND 64),
    provider_display_name TEXT NOT NULL CHECK(length(trim(provider_display_name)) BETWEEN 1 AND 80),
    api_base_url TEXT NOT NULL CHECK(length(api_base_url) BETWEEN 1 AND 2048),
    management_url TEXT CHECK(management_url IS NULL OR length(management_url) BETWEEN 1 AND 2048),
    auth_mode TEXT NOT NULL CHECK(auth_mode IN ('api_key', 'oauth')),
    credential_ref_id TEXT NOT NULL,
    default_model_preset_id TEXT,
    status TEXT NOT NULL CHECK(status IN ('draft', 'ready', 'disabled')),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= created_at_unix_ms),
    version INTEGER NOT NULL CHECK(version >= 1),
    CHECK(
        (status = 'draft' AND default_model_preset_id IS NULL)
        OR (status IN ('ready', 'disabled') AND default_model_preset_id IS NOT NULL)
    ),
    UNIQUE(provider_id, api_base_url, credential_ref_id),
    FOREIGN KEY(credential_ref_id, auth_mode)
        REFERENCES credential_references(id, auth_mode) ON DELETE RESTRICT,
    FOREIGN KEY(default_model_preset_id, id)
        REFERENCES model_presets(id, identity_id)
        ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE model_presets (
    id TEXT PRIMARY KEY
        CHECK(length(id) = 36 AND substr(id, 9, 1) = '-' AND substr(id, 14, 1) = '-'
            AND substr(id, 19, 1) = '-' AND substr(id, 24, 1) = '-'
            AND id NOT GLOB '*[^0-9a-f-]*'),
    identity_id TEXT NOT NULL REFERENCES runtime_identities(id) ON DELETE CASCADE,
    name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 80),
    model_id TEXT NOT NULL CHECK(length(model_id) BETWEEN 1 AND 128),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= created_at_unix_ms),
    version INTEGER NOT NULL CHECK(version >= 1),
    UNIQUE(identity_id, name),
    UNIQUE(id, identity_id)
) STRICT;

CREATE INDEX idx_runtime_identities_candidate
    ON runtime_identities(provider_id, api_base_url, auth_mode, credential_ref_id);

CREATE INDEX idx_model_presets_identity
    ON model_presets(identity_id, name, id);
