CREATE TABLE switch_sensitive_temp_owners (
    transaction_id TEXT NOT NULL,
    root_ref TEXT NOT NULL CHECK(length(root_ref) = 64),
    role TEXT NOT NULL CHECK(role IN ('config', 'auth')),
    phase TEXT NOT NULL CHECK(phase IN ('target', 'recovery')),
    nonce BLOB NOT NULL CHECK(length(nonce) = 16),
    temp_rel TEXT NOT NULL,
    publish_rel TEXT NOT NULL CHECK(publish_rel IN ('config.toml', 'auth.json')),
    identity_bound INTEGER NOT NULL CHECK(identity_bound IN (0, 1)),
    volume_serial BLOB CHECK(volume_serial IS NULL OR length(volume_serial) = 8),
    file_id BLOB CHECK(file_id IS NULL OR length(file_id) = 16),
    expected_length INTEGER NOT NULL CHECK(expected_length >= 0),
    expected_sha256 TEXT NOT NULL CHECK(length(expected_sha256) = 64),
    expected_readonly INTEGER NOT NULL CHECK(expected_readonly IN (0, 1)),
    lifecycle TEXT NOT NULL CHECK(lifecycle IN (
        'prewrite_delete_armed', 'owned', 'published', 'cleanup_delete_armed'
    )),
    destination_state TEXT NOT NULL CHECK(destination_state IN (
        'none', 'readonly_clear_armed', 'readonly_cleared'
    )),
    destination_volume_serial BLOB CHECK(
        destination_volume_serial IS NULL OR length(destination_volume_serial) = 8
    ),
    destination_file_id BLOB CHECK(
        destination_file_id IS NULL OR length(destination_file_id) = 16
    ),
    destination_length INTEGER CHECK(destination_length IS NULL OR destination_length >= 0),
    destination_readonly INTEGER CHECK(destination_readonly IS NULL OR destination_readonly IN (0, 1)),
    destination_hash_ref TEXT CHECK(
        destination_hash_ref IS NULL OR length(destination_hash_ref) = 64
    ),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= created_at_unix_ms),
    version INTEGER NOT NULL CHECK(version >= 1),
    PRIMARY KEY(transaction_id, phase, role),
    UNIQUE(root_ref, temp_rel),
    UNIQUE(root_ref, nonce),
    FOREIGN KEY(transaction_id) REFERENCES switch_transactions(id) ON DELETE RESTRICT,
    CHECK(
        (identity_bound = 0 AND volume_serial IS NULL AND file_id IS NULL
            AND lifecycle = 'prewrite_delete_armed') OR
        (identity_bound = 1 AND volume_serial IS NOT NULL AND file_id IS NOT NULL)
    ),
    CHECK(
        (role = 'config' AND publish_rel = 'config.toml') OR
        (role = 'auth' AND publish_rel = 'auth.json')
    ),
    CHECK(
        temp_rel = '.' || publish_rel || '.' || transaction_id || '.' || lower(hex(nonce)) ||
            CASE phase WHEN 'target' THEN '.stage' ELSE '.recovery' END
    ),
    CHECK(
        (destination_state = 'none' AND destination_volume_serial IS NULL
            AND destination_file_id IS NULL AND destination_length IS NULL
            AND destination_readonly IS NULL AND destination_hash_ref IS NULL) OR
        (destination_state IN ('readonly_clear_armed', 'readonly_cleared')
            AND destination_volume_serial IS NOT NULL AND destination_file_id IS NOT NULL
            AND destination_length IS NOT NULL AND destination_readonly = 1
            AND destination_hash_ref IS NOT NULL)
    )
) STRICT;

CREATE INDEX idx_switch_sensitive_temp_owners_root
    ON switch_sensitive_temp_owners(root_ref, transaction_id, phase, role);

CREATE TRIGGER switch_sensitive_temp_owner_root_insert
BEFORE INSERT ON switch_sensitive_temp_owners
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1 FROM switch_transactions
    WHERE id = NEW.transaction_id AND root_ref = NEW.root_ref
)
BEGIN
    SELECT RAISE(ABORT, 'sensitive temp owner root mismatch');
END;

CREATE TRIGGER switch_sensitive_temp_owner_immutable
BEFORE UPDATE ON switch_sensitive_temp_owners
FOR EACH ROW
WHEN NEW.transaction_id <> OLD.transaction_id
  OR NEW.root_ref <> OLD.root_ref
  OR NEW.role <> OLD.role
  OR NEW.phase <> OLD.phase
  OR NEW.nonce <> OLD.nonce
  OR NEW.temp_rel <> OLD.temp_rel
  OR NEW.publish_rel <> OLD.publish_rel
  OR (OLD.identity_bound = 1 AND (
        NEW.identity_bound <> OLD.identity_bound
        OR NEW.volume_serial <> OLD.volume_serial
        OR NEW.file_id <> OLD.file_id
     ))
  OR (OLD.identity_bound = 0 AND NOT (
        (NEW.identity_bound = 0 AND NEW.volume_serial IS NULL AND NEW.file_id IS NULL) OR
        (NEW.identity_bound = 1 AND NEW.volume_serial IS NOT NULL AND NEW.file_id IS NOT NULL)
     ))
  OR NEW.expected_length <> OLD.expected_length
  OR NEW.expected_sha256 <> OLD.expected_sha256
  OR NEW.expected_readonly <> OLD.expected_readonly
  OR NEW.created_at_unix_ms <> OLD.created_at_unix_ms
BEGIN
    SELECT RAISE(ABORT, 'sensitive temp owner immutable binding');
END;

CREATE TRIGGER switch_sensitive_temp_owner_lifecycle
BEFORE UPDATE OF lifecycle ON switch_sensitive_temp_owners
FOR EACH ROW
WHEN NOT (
    (OLD.lifecycle = 'prewrite_delete_armed' AND NEW.lifecycle IN ('owned', 'cleanup_delete_armed')) OR
    (OLD.lifecycle = 'owned' AND NEW.lifecycle IN ('published', 'cleanup_delete_armed')) OR
    (OLD.lifecycle = NEW.lifecycle)
)
BEGIN
    SELECT RAISE(ABORT, 'invalid sensitive temp owner lifecycle');
END;

CREATE TRIGGER switch_sensitive_temp_owner_destination_guard
BEFORE UPDATE ON switch_sensitive_temp_owners
FOR EACH ROW
WHEN NOT (
    (OLD.destination_state = NEW.destination_state) OR
    (OLD.destination_state = 'none' AND NEW.destination_state = 'readonly_clear_armed') OR
    (OLD.destination_state = 'readonly_clear_armed' AND NEW.destination_state IN ('readonly_cleared', 'none')) OR
    (OLD.destination_state = 'readonly_cleared' AND NEW.destination_state = 'none')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid readonly destination guard transition');
END;

CREATE TRIGGER switch_sensitive_temp_owner_blocks_terminal
BEFORE UPDATE OF state ON switch_transactions
FOR EACH ROW
WHEN NEW.state IN ('committed', 'rolled_back')
 AND EXISTS (
    SELECT 1 FROM switch_sensitive_temp_owners owner
    WHERE owner.transaction_id = NEW.id
 )
BEGIN
    SELECT RAISE(ABORT, 'sensitive temp owner blocks terminal transaction');
END;

CREATE TABLE switch_sensitive_temp_anomalies (
    transaction_id TEXT,
    root_ref TEXT NOT NULL CHECK(length(root_ref) = 64),
    role TEXT NOT NULL CHECK(role IN ('config', 'auth')),
    phase TEXT NOT NULL CHECK(phase IN ('target', 'recovery')),
    canonical_rel_path TEXT NOT NULL,
    reason TEXT NOT NULL CHECK(reason IN (
        'legacy_partial', 'legacy_mismatch', 'identity_mismatch', 'reparse',
        'query_error', 'illegal_path', 'capability_unknown'
    )),
    observed_volume_serial BLOB CHECK(
        observed_volume_serial IS NULL OR length(observed_volume_serial) = 8
    ),
    observed_file_id BLOB CHECK(observed_file_id IS NULL OR length(observed_file_id) = 16),
    observed_length INTEGER CHECK(observed_length IS NULL OR observed_length >= 0),
    created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms >= 0),
    updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms >= created_at_unix_ms),
    version INTEGER NOT NULL CHECK(version >= 1),
    PRIMARY KEY(root_ref, canonical_rel_path),
    FOREIGN KEY(transaction_id) REFERENCES switch_transactions(id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX idx_switch_sensitive_temp_anomalies_root
    ON switch_sensitive_temp_anomalies(root_ref, transaction_id, phase, role);

CREATE TRIGGER switch_sensitive_temp_anomaly_root_insert
BEFORE INSERT ON switch_sensitive_temp_anomalies
FOR EACH ROW
WHEN NEW.transaction_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM switch_transactions
    WHERE id = NEW.transaction_id AND root_ref = NEW.root_ref
)
BEGIN
    SELECT RAISE(ABORT, 'sensitive temp anomaly root mismatch');
END;

CREATE TRIGGER switch_sensitive_temp_anomaly_identity_immutable
BEFORE UPDATE ON switch_sensitive_temp_anomalies
FOR EACH ROW
WHEN NEW.transaction_id IS NOT OLD.transaction_id
  OR NEW.root_ref <> OLD.root_ref
  OR NEW.role <> OLD.role
  OR NEW.phase <> OLD.phase
  OR NEW.canonical_rel_path <> OLD.canonical_rel_path
  OR NEW.created_at_unix_ms <> OLD.created_at_unix_ms
BEGIN
    SELECT RAISE(ABORT, 'sensitive temp anomaly immutable binding');
END;
