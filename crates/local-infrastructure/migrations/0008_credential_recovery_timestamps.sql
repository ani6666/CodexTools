-- A v7 delete_pending row without its exact credential metadata may have lost
-- the rotated credential updated_at. Abort atomically rather than guess.
CREATE TEMP TABLE m24_v8_delete_timestamp_guard (
    ambiguous_count INTEGER NOT NULL CHECK(ambiguous_count = 0)
) STRICT;

INSERT INTO m24_v8_delete_timestamp_guard(ambiguous_count)
SELECT COUNT(*)
FROM credential_recovery_operations AS recovery
LEFT JOIN credential_references AS credential
  ON credential.id = recovery.credential_id
 AND credential.version = recovery.generation
WHERE recovery.operation = 'delete'
  AND recovery.phase = 'delete_pending'
  AND credential.id IS NULL;

DROP TABLE m24_v8_delete_timestamp_guard;
DROP INDEX ux_credential_recovery_active;
DROP INDEX idx_credential_recovery_unresolved;

ALTER TABLE credential_recovery_operations
RENAME TO credential_recovery_operations_v7;

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
    credential_created_at_unix_ms INTEGER NOT NULL CHECK(credential_created_at_unix_ms >= 0),
    credential_updated_at_unix_ms INTEGER NOT NULL CHECK(credential_updated_at_unix_ms >= credential_created_at_unix_ms),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= created_at_unix_ms),
    version INTEGER NOT NULL CHECK(version >= 1),
    CHECK((phase = 'prepared' AND material_sha256 IS NULL) OR (phase <> 'prepared' AND material_sha256 IS NOT NULL))
) STRICT;

INSERT INTO credential_recovery_operations(
    operation_id,credential_id,kind,operation,generation,material_ref,
    material_sha256,phase,diagnostic_code,credential_created_at_unix_ms,
    credential_updated_at_unix_ms,created_at_unix_ms,updated_at_unix_ms,version
)
SELECT
    recovery.operation_id,recovery.credential_id,recovery.kind,recovery.operation,
    recovery.generation,recovery.material_ref,recovery.material_sha256,recovery.phase,
    recovery.diagnostic_code,
    COALESCE(credential.created_at_unix_ms,
             current_credential.created_at_unix_ms,
             recovery.created_at_unix_ms),
    COALESCE(credential.updated_at_unix_ms,
             CASE recovery.operation
                 WHEN 'create' THEN recovery.created_at_unix_ms
                 WHEN 'rotate' THEN recovery.created_at_unix_ms
                 ELSE recovery.updated_at_unix_ms
             END),
    recovery.created_at_unix_ms,recovery.updated_at_unix_ms,recovery.version
FROM credential_recovery_operations_v7 AS recovery
LEFT JOIN credential_references AS credential
  ON credential.id = recovery.credential_id
 AND credential.version = recovery.generation
LEFT JOIN credential_references AS current_credential
  ON current_credential.id = recovery.credential_id;

DROP TABLE credential_recovery_operations_v7;

CREATE INDEX idx_credential_recovery_unresolved
ON credential_recovery_operations(credential_id, phase, generation, operation_id);

CREATE UNIQUE INDEX ux_credential_recovery_active
ON credential_recovery_operations(credential_id);
