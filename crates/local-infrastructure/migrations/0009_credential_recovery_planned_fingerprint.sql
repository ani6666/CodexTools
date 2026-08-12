ALTER TABLE credential_recovery_operations
ADD COLUMN planned_credential_fingerprint TEXT
CHECK(planned_credential_fingerprint IS NULL OR (
    length(planned_credential_fingerprint) = 64
    AND planned_credential_fingerprint NOT GLOB '*[^0-9a-f]*'
));

ALTER TABLE credential_recovery_operations
ADD COLUMN legacy_unbound INTEGER NOT NULL DEFAULT 1
CHECK(legacy_unbound IN (0,1));

UPDATE credential_recovery_operations
SET planned_credential_fingerprint = (
        SELECT credential_fingerprint
        FROM credential_references
        WHERE credential_references.id = credential_recovery_operations.credential_id
          AND credential_references.version = credential_recovery_operations.generation
    ),
    legacy_unbound = 0
WHERE EXISTS (
    SELECT 1
    FROM credential_references
    WHERE credential_references.id = credential_recovery_operations.credential_id
      AND credential_references.version = credential_recovery_operations.generation
);

CREATE TRIGGER trg_credential_recovery_planned_fingerprint_insert
BEFORE INSERT ON credential_recovery_operations
WHEN NEW.legacy_unbound <> 0 OR NEW.planned_credential_fingerprint IS NULL
BEGIN
    SELECT RAISE(ABORT, 'planned credential fingerprint required');
END;

CREATE TRIGGER trg_credential_recovery_planned_fingerprint_immutable
BEFORE UPDATE OF planned_credential_fingerprint, legacy_unbound
ON credential_recovery_operations
WHEN NEW.planned_credential_fingerprint IS NOT OLD.planned_credential_fingerprint
  OR NEW.legacy_unbound <> OLD.legacy_unbound
BEGIN
    SELECT RAISE(ABORT, 'planned credential fingerprint is immutable');
END;
