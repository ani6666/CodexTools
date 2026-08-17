CREATE TABLE capture_import_operations (
    operation_id TEXT PRIMARY KEY
        CHECK(length(operation_id) BETWEEN 1 AND 96),
    root_selector TEXT NOT NULL
        CHECK(root_selector = 'default_codex'),
    scan_id TEXT NOT NULL
        CHECK(length(scan_id) = 64 AND scan_id NOT GLOB '*[^0-9a-f]*'),
    credential_id TEXT NOT NULL
        CHECK(length(credential_id) = 36 AND credential_id NOT GLOB '*[^0-9a-f-]*'),
    identity_id TEXT NOT NULL
        CHECK(length(identity_id) = 36 AND identity_id NOT GLOB '*[^0-9a-f-]*'),
    identity_name TEXT NOT NULL CHECK(length(trim(identity_name)) BETWEEN 1 AND 80),
    preset_id TEXT NOT NULL
        CHECK(length(preset_id) = 36 AND preset_id NOT GLOB '*[^0-9a-f-]*'),
    preset_name TEXT NOT NULL CHECK(length(trim(preset_name)) BETWEEN 1 AND 80),
    patch_id TEXT NOT NULL
        CHECK(length(patch_id) = 36 AND patch_id NOT GLOB '*[^0-9a-f-]*'),
    auth_mode TEXT NOT NULL CHECK(auth_mode IN ('api_key','oauth')),
    auth_schema_fingerprint TEXT NOT NULL
        CHECK(length(auth_schema_fingerprint) = 64 AND auth_schema_fingerprint NOT GLOB '*[^0-9a-f]*'),
    credential_origin TEXT NOT NULL CHECK(credential_origin IN ('created','reused')),
    credential_backend TEXT NOT NULL CHECK(credential_backend = 'windows_dpapi_current_user'),
    credential_schema_fingerprint TEXT NOT NULL
        CHECK(length(credential_schema_fingerprint) = 64 AND credential_schema_fingerprint NOT GLOB '*[^0-9a-f]*'),
    credential_fingerprint TEXT NOT NULL
        CHECK(length(credential_fingerprint) = 64 AND credential_fingerprint NOT GLOB '*[^0-9a-f]*'),
    credential_version INTEGER NOT NULL CHECK(credential_version >= 1),
    credential_created_at_unix_ms INTEGER NOT NULL CHECK(credential_created_at_unix_ms >= 0),
    credential_updated_at_unix_ms INTEGER NOT NULL
        CHECK(credential_updated_at_unix_ms >= credential_created_at_unix_ms),
    provider_id TEXT NOT NULL CHECK(length(provider_id) BETWEEN 1 AND 64),
    provider_display_name TEXT NOT NULL
        CHECK(length(trim(provider_display_name)) BETWEEN 1 AND 80),
    api_base_url TEXT NOT NULL CHECK(length(api_base_url) BETWEEN 1 AND 2048),
    model_id TEXT NOT NULL CHECK(length(model_id) BETWEEN 1 AND 128),
    config_hash TEXT NOT NULL
        CHECK(length(config_hash) = 64 AND config_hash NOT GLOB '*[^0-9a-f]*'),
    phase TEXT NOT NULL
        CHECK(phase IN ('prepared','credential_ready','bundle_ready','recovery_required')),
    diagnostic_code TEXT
        CHECK(diagnostic_code IS NULL OR diagnostic_code IN (
            'journal_unavailable','credential_pending','bundle_pending',
            'cleanup_pending','inconsistent_state'
        )),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= created_at_unix_ms),
    version INTEGER NOT NULL CHECK(version >= 1),
    UNIQUE(identity_id),
    UNIQUE(credential_id)
) STRICT;

CREATE INDEX idx_capture_import_unfinished
ON capture_import_operations(phase, operation_id);
