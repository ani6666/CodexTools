CREATE TABLE backup_sets (
    id TEXT PRIMARY KEY CHECK(length(id) BETWEEN 1 AND 80),
    root_ref TEXT NOT NULL CHECK(length(root_ref) = 64 AND root_ref NOT GLOB '*[^0-9a-f]*'),
    kind TEXT NOT NULL CHECK(kind IN ('permanent','history')),
    sequence INTEGER NOT NULL CHECK(sequence >= 0),
    manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256) = 64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'),
    material_ref TEXT NOT NULL CHECK(length(material_ref) BETWEEN 1 AND 512 AND material_ref NOT LIKE '%..%'),
    transaction_id TEXT REFERENCES switch_transactions(id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK(state IN ('ready','protected')),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    UNIQUE(root_ref, kind, sequence)
) STRICT;

CREATE UNIQUE INDEX ux_backup_sets_permanent_root
ON backup_sets(root_ref)
WHERE kind = 'permanent';

CREATE INDEX idx_backup_sets_history_rotation
ON backup_sets(root_ref, kind, sequence, created_at_unix_ms, id);
