CREATE TABLE backup_recovery_operations (
    operation_id TEXT PRIMARY KEY CHECK(length(operation_id) BETWEEN 1 AND 96),
    root_ref TEXT NOT NULL CHECK(length(root_ref) = 64 AND root_ref NOT GLOB '*[^0-9a-f]*'),
    operation TEXT NOT NULL CHECK(operation IN ('publish','delete')),
    phase TEXT NOT NULL CHECK(phase IN ('prepared','published','renamed','metadata_deleted','recovery_required')),
    backup_id TEXT NOT NULL CHECK(length(backup_id) BETWEEN 1 AND 80),
    kind TEXT NOT NULL CHECK(kind IN ('permanent','history')),
    sequence INTEGER NOT NULL CHECK(sequence >= 0),
    manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256) = 64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'),
    material_ref TEXT NOT NULL CHECK(length(material_ref) BETWEEN 1 AND 512 AND material_ref NOT LIKE '%..%'),
    pending_ref TEXT CHECK(pending_ref IS NULL OR (length(pending_ref) BETWEEN 1 AND 512 AND pending_ref NOT LIKE '%..%')),
    transaction_id TEXT REFERENCES switch_transactions(id) ON DELETE RESTRICT,
    backup_state TEXT NOT NULL CHECK(backup_state IN ('ready','protected')),
    backup_created_at_unix_ms INTEGER NOT NULL CHECK(backup_created_at_unix_ms >= 0),
    diagnostic_code TEXT CHECK(diagnostic_code IS NULL OR (length(diagnostic_code) BETWEEN 1 AND 64 AND diagnostic_code NOT GLOB '*[^a-z0-9_]*'))
) STRICT;

CREATE UNIQUE INDEX ux_backup_recovery_root
ON backup_recovery_operations(root_ref);

CREATE INDEX idx_backup_recovery_backup
ON backup_recovery_operations(backup_id, operation, phase);

CREATE TABLE credential_recovery_operations (
    operation_id TEXT PRIMARY KEY CHECK(length(operation_id) BETWEEN 1 AND 96),
    credential_id TEXT NOT NULL CHECK(length(credential_id) = 36),
    kind TEXT NOT NULL CHECK(kind IN ('api_key','oauth_bundle')),
    operation TEXT NOT NULL CHECK(operation IN ('create','rotate','delete')),
    generation INTEGER NOT NULL CHECK(generation >= 1),
    material_ref TEXT NOT NULL CHECK(length(material_ref) BETWEEN 1 AND 512 AND material_ref NOT LIKE '%..%'),
    material_sha256 TEXT CHECK(material_sha256 IS NULL OR (length(material_sha256) = 64 AND material_sha256 NOT GLOB '*[^0-9a-f]*')),
    phase TEXT NOT NULL CHECK(phase IN ('prepared','published','metadata_pending','delete_pending','recovery_required')),
    diagnostic_code TEXT CHECK(diagnostic_code IS NULL OR (length(diagnostic_code) BETWEEN 1 AND 64 AND diagnostic_code NOT GLOB '*[^a-z0-9_]*')),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= created_at_unix_ms),
    version INTEGER NOT NULL CHECK(version >= 1),
    CHECK((phase = 'prepared' AND material_sha256 IS NULL) OR (phase <> 'prepared' AND material_sha256 IS NOT NULL))
) STRICT;

CREATE INDEX idx_credential_recovery_unresolved
ON credential_recovery_operations(credential_id, phase, generation, operation_id);
