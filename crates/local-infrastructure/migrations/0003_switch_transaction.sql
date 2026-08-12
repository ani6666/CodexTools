CREATE TABLE switch_transactions (
    id TEXT PRIMARY KEY CHECK(length(id) = 36),
    root_ref TEXT NOT NULL CHECK(length(root_ref) = 64 AND root_ref NOT GLOB '*[^0-9a-f]*'),
    config_source_sha256 TEXT CHECK(config_source_sha256 IS NULL OR (length(config_source_sha256) = 64 AND config_source_sha256 NOT GLOB '*[^0-9a-f]*')),
    auth_source_sha256 TEXT CHECK(auth_source_sha256 IS NULL OR (length(auth_source_sha256) = 64 AND auth_source_sha256 NOT GLOB '*[^0-9a-f]*')),
    config_target_sha256 TEXT NOT NULL CHECK(length(config_target_sha256) = 64 AND config_target_sha256 NOT GLOB '*[^0-9a-f]*'),
    auth_target_sha256 TEXT NOT NULL CHECK(length(auth_target_sha256) = 64 AND auth_target_sha256 NOT GLOB '*[^0-9a-f]*'),
    target_provider_id TEXT NOT NULL CHECK(length(target_provider_id) BETWEEN 1 AND 64),
    target_model_id TEXT NOT NULL CHECK(length(target_model_id) BETWEEN 1 AND 128),
    target_auth_fingerprint TEXT NOT NULL CHECK(length(target_auth_fingerprint) = 64 AND target_auth_fingerprint NOT GLOB '*[^0-9a-f]*'),
    snapshot_manifest_sha256 TEXT CHECK(snapshot_manifest_sha256 IS NULL OR (length(snapshot_manifest_sha256) = 64 AND snapshot_manifest_sha256 NOT GLOB '*[^0-9a-f]*')),
    state TEXT NOT NULL CHECK(state IN ('planned','lock_acquired','snapshot_created','targets_staged','replacing','targets_replaced','verified','committed','rolling_back','rolled_back','recovery_required')),
    completed_roles INTEGER NOT NULL CHECK(completed_roles BETWEEN 0 AND 3),
    last_error_code TEXT CHECK(last_error_code IS NULL OR last_error_code IN ('busy','plan_stale','compatibility_protected','snapshot_invalid','io_failure','repository_failure','injected_failure','recovery_required')),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= created_at_unix_ms),
    version INTEGER NOT NULL CHECK(version >= 1),
    CHECK(
        (state IN ('planned','lock_acquired','snapshot_created','targets_staged') AND completed_roles = 0)
        OR (state = 'replacing')
        OR (state IN ('targets_replaced','verified','committed') AND completed_roles = 3)
        OR (state IN ('rolling_back','rolled_back','recovery_required'))
    ),
    CHECK(
        (state IN ('planned','lock_acquired') AND snapshot_manifest_sha256 IS NULL)
        OR (state IN ('snapshot_created','targets_staged','replacing','targets_replaced','verified','committed') AND snapshot_manifest_sha256 IS NOT NULL)
        OR (state IN ('rolling_back','rolled_back','recovery_required'))
    )
) STRICT;
CREATE INDEX idx_switch_transactions_recovery ON switch_transactions(root_ref, state, created_at_unix_ms, id);
