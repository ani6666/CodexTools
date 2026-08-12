CREATE TABLE managed_config_patches (
    id TEXT PRIMARY KEY
        CHECK(length(id) = 36 AND substr(id, 9, 1) = '-' AND substr(id, 14, 1) = '-'
            AND substr(id, 19, 1) = '-' AND substr(id, 24, 1) = '-'
            AND id NOT GLOB '*[^0-9a-f-]*'),
    identity_id TEXT NOT NULL UNIQUE REFERENCES runtime_identities(id) ON DELETE CASCADE,
    baseline_sha256 TEXT NOT NULL
        CHECK(length(baseline_sha256) = 64 AND baseline_sha256 NOT GLOB '*[^0-9a-f]*'),
    target_sha256 TEXT NOT NULL
        CHECK(length(target_sha256) = 64 AND target_sha256 NOT GLOB '*[^0-9a-f]*'),
    managed_paths_version INTEGER NOT NULL CHECK(managed_paths_version = 1),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= created_at_unix_ms),
    version INTEGER NOT NULL CHECK(version >= 1)
) STRICT;

CREATE INDEX idx_managed_config_patches_identity
    ON managed_config_patches(identity_id, id);
