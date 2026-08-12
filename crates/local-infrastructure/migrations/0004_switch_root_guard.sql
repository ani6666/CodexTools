CREATE UNIQUE INDEX ux_switch_transactions_active_root
ON switch_transactions(root_ref)
WHERE state NOT IN ('committed','rolled_back');

CREATE TRIGGER trg_switch_snapshot_binding_insert
BEFORE INSERT ON switch_transactions
WHEN NEW.snapshot_manifest_sha256 IS NULL AND NEW.completed_roles <> 0
BEGIN
    SELECT RAISE(ABORT, 'switch snapshot binding required');
END;

CREATE TRIGGER trg_switch_snapshot_binding_update
BEFORE UPDATE ON switch_transactions
WHEN (OLD.snapshot_manifest_sha256 IS NOT NULL AND NEW.snapshot_manifest_sha256 IS NULL)
  OR (NEW.snapshot_manifest_sha256 IS NULL AND NEW.completed_roles <> 0)
BEGIN
    SELECT RAISE(ABORT, 'switch snapshot binding invalid');
END;
