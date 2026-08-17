use codex_application::{
    CaptureImportBundlePreflight, CaptureImportBundleRepository, CaptureImportRecoveryRecord,
    EntityKind, IdentityBundle, IdentityBundleRepository, ManagedConfigPatchRepository,
    RepositoryError,
};
use codex_domain::{
    AuthMode, ContentHash, CredentialKind, IdentityStatus, ManagedConfigPatch,
    ManagedConfigPatchId, ModelPresetId,
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

use crate::{SqliteMetadataRepository, repository::map_write_error};

fn version(value: codex_domain::EntityVersion) -> i64 {
    value.value() as i64
}

impl IdentityBundleRepository for SqliteMetadataRepository {
    fn create_identity_bundle(&mut self, bundle: &IdentityBundle) -> Result<(), RepositoryError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| RepositoryError::storage_unavailable())?;
        if let Some(reference) = &bundle.credential_to_create {
            transaction.execute("INSERT INTO credential_references (id,kind,platform_backend,schema_fingerprint,credential_fingerprint,created_at_unix_ms,updated_at_unix_ms,version) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",params![reference.id().as_str(),reference.kind().as_storage_str(),reference.backend().as_storage_str(),reference.schema_fingerprint().as_str(),reference.credential_fingerprint().as_str(),reference.created_at().value(),reference.updated_at().value(),version(reference.version())]).map_err(|error|map_write_error(error,EntityKind::CredentialReference,None))?;
        }
        let identity = &bundle.identity;
        transaction.execute("INSERT INTO runtime_identities (id,name,provider_id,provider_display_name,api_base_url,management_url,auth_mode,credential_ref_id,default_model_preset_id,status,created_at_unix_ms,updated_at_unix_ms,version) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",params![identity.id().as_str(),identity.name().as_str(),identity.provider_id().as_str(),identity.provider_display_name().as_str(),identity.api_base_url().as_str(),identity.management_url().map(|v|v.as_str()),identity.auth_mode().as_storage_str(),identity.credential().id().as_str(),identity.default_model_preset_id().map(ModelPresetId::as_str),identity.status().as_storage_str(),identity.created_at().value(),identity.updated_at().value(),version(identity.version())]).map_err(|error|map_write_error(error,EntityKind::RuntimeIdentity,Some(EntityKind::CredentialReference)))?;
        let preset = &bundle.preset;
        transaction.execute("INSERT INTO model_presets (id,identity_id,name,model_id,created_at_unix_ms,updated_at_unix_ms,version) VALUES (?1,?2,?3,?4,?5,?6,?7)",params![preset.id().as_str(),preset.identity_id().as_str(),preset.name().as_str(),preset.model_id().as_str(),preset.created_at().value(),preset.updated_at().value(),version(preset.version())]).map_err(|error|map_write_error(error,EntityKind::ModelPreset,Some(EntityKind::RuntimeIdentity)))?;
        insert_patch(&transaction, &bundle.patch)?;
        transaction.commit().map_err(|error| {
            map_write_error(
                error,
                EntityKind::RuntimeIdentity,
                Some(EntityKind::ModelPreset),
            )
        })
    }
}

impl CaptureImportBundleRepository for SqliteMetadataRepository {
    fn preflight_capture_import(
        &self,
        record: &CaptureImportRecoveryRecord,
    ) -> Result<CaptureImportBundlePreflight, RepositoryError> {
        let credential_kind = match record.auth_mode {
            AuthMode::ApiKey => "api_key",
            AuthMode::OAuth => "oauth_bundle",
        };
        let credential_conflict: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM credential_references
             WHERE id=?1 AND NOT (kind=?2 AND credential_fingerprint=?3)",
                params![
                    record.credential_id.as_str(),
                    credential_kind,
                    record.credential_fingerprint.as_str()
                ],
                |row| row.get(0),
            )
            .map_err(|_| RepositoryError::storage_unavailable())?;
        let identity_conflict: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM runtime_identities
             WHERE id=?1 OR (provider_id=?2 AND api_base_url=?3 AND credential_ref_id=?4)",
                params![
                    record.identity_id.as_str(),
                    record.provider_id.as_str(),
                    record.api_base_url.as_str(),
                    record.credential_id.as_str()
                ],
                |row| row.get(0),
            )
            .map_err(|_| RepositoryError::storage_unavailable())?;
        let preset_conflict: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM model_presets WHERE id=?1 OR (identity_id=?2 AND name=?3)",
                params![
                    record.preset_id.as_str(),
                    record.identity_id.as_str(),
                    record.preset_name.as_str()
                ],
                |row| row.get(0),
            )
            .map_err(|_| RepositoryError::storage_unavailable())?;
        let patch_conflict: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM managed_config_patches WHERE id=?1 OR identity_id=?2",
                params![record.patch_id.as_str(), record.identity_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| RepositoryError::storage_unavailable())?;
        Ok(
            if credential_conflict == 0
                && identity_conflict == 0
                && preset_conflict == 0
                && patch_conflict == 0
            {
                CaptureImportBundlePreflight::Available
            } else {
                CaptureImportBundlePreflight::Conflict
            },
        )
    }

    fn create_identity_bundle_if_credential_exact(
        &mut self,
        bundle: &IdentityBundle,
        expected: &codex_domain::CredentialReference,
    ) -> Result<(), RepositoryError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| RepositoryError::storage_unavailable())?;
        let exact: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM credential_references
             WHERE id=?1 AND kind=?2 AND platform_backend=?3 AND schema_fingerprint=?4
               AND credential_fingerprint=?5 AND created_at_unix_ms=?6
               AND updated_at_unix_ms=?7 AND version=?8",
                params![
                    expected.id().as_str(),
                    expected.kind().as_storage_str(),
                    expected.backend().as_storage_str(),
                    expected.schema_fingerprint().as_str(),
                    expected.credential_fingerprint().as_str(),
                    expected.created_at().value(),
                    expected.updated_at().value(),
                    version(expected.version()),
                ],
                |row| row.get(0),
            )
            .map_err(|_| RepositoryError::storage_unavailable())?;
        if exact != 1 {
            return Err(RepositoryError::version_conflict(
                EntityKind::CredentialReference,
            ));
        }
        insert_bundle_rows(&transaction, bundle)?;
        transaction.commit().map_err(|error| {
            map_write_error(
                error,
                EntityKind::RuntimeIdentity,
                Some(EntityKind::ModelPreset),
            )
        })
    }

    fn capture_import_target_is_empty(
        &self,
        record: &CaptureImportRecoveryRecord,
    ) -> Result<bool, RepositoryError> {
        let identity_count: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM runtime_identities WHERE id=?1",
                [record.identity_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| RepositoryError::storage_unavailable())?;
        let preset_count: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM model_presets WHERE identity_id=?1",
                [record.identity_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| RepositoryError::storage_unavailable())?;
        let patch_count: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM managed_config_patches WHERE identity_id=?1",
                [record.identity_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| RepositoryError::storage_unavailable())?;
        Ok(identity_count == 0 && preset_count == 0 && patch_count == 0)
    }
}

fn insert_bundle_rows(
    connection: &rusqlite::Connection,
    bundle: &IdentityBundle,
) -> Result<(), RepositoryError> {
    let identity = &bundle.identity;
    connection.execute("INSERT INTO runtime_identities (id,name,provider_id,provider_display_name,api_base_url,management_url,auth_mode,credential_ref_id,default_model_preset_id,status,created_at_unix_ms,updated_at_unix_ms,version) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",params![identity.id().as_str(),identity.name().as_str(),identity.provider_id().as_str(),identity.provider_display_name().as_str(),identity.api_base_url().as_str(),identity.management_url().map(|v|v.as_str()),identity.auth_mode().as_storage_str(),identity.credential().id().as_str(),identity.default_model_preset_id().map(ModelPresetId::as_str),identity.status().as_storage_str(),identity.created_at().value(),identity.updated_at().value(),version(identity.version())]).map_err(|error|map_write_error(error,EntityKind::RuntimeIdentity,Some(EntityKind::CredentialReference)))?;
    let preset = &bundle.preset;
    connection.execute("INSERT INTO model_presets (id,identity_id,name,model_id,created_at_unix_ms,updated_at_unix_ms,version) VALUES (?1,?2,?3,?4,?5,?6,?7)",params![preset.id().as_str(),preset.identity_id().as_str(),preset.name().as_str(),preset.model_id().as_str(),preset.created_at().value(),preset.updated_at().value(),version(preset.version())]).map_err(|error|map_write_error(error,EntityKind::ModelPreset,Some(EntityKind::RuntimeIdentity)))?;
    insert_patch(connection, &bundle.patch)
}

fn insert_patch(
    connection: &rusqlite::Connection,
    patch: &ManagedConfigPatch,
) -> Result<(), RepositoryError> {
    connection.execute("INSERT INTO managed_config_patches (id,identity_id,baseline_sha256,target_sha256,managed_paths_version,created_at_unix_ms,updated_at_unix_ms,version) VALUES (?1,?2,?3,?4,1,?5,?6,?7)",params![patch.id().as_str(),patch.identity_id().as_str(),patch.baseline_sha256().as_str(),patch.target_sha256().as_str(),patch.created_at().value(),patch.updated_at().value(),version(patch.version())]).map_err(|error|map_write_error(error,EntityKind::ManagedConfigPatch,Some(EntityKind::RuntimeIdentity)))?;
    Ok(())
}

impl ManagedConfigPatchRepository for SqliteMetadataRepository {
    fn create_managed_config_patch(
        &mut self,
        patch: &ManagedConfigPatch,
    ) -> Result<(), RepositoryError> {
        insert_patch(&self.connection, patch)
    }
    fn get_managed_config_patch(
        &self,
        identity_id: &codex_domain::IdentityId,
    ) -> Result<Option<ManagedConfigPatch>, RepositoryError> {
        self.connection.query_row("SELECT id,identity_id,baseline_sha256,target_sha256,created_at_unix_ms,updated_at_unix_ms,version FROM managed_config_patches WHERE identity_id=?1",[identity_id.as_str()],|row|{
            ManagedConfigPatch::restore(
                ManagedConfigPatchId::parse(&row.get::<_,String>(0)?).map_err(|_|rusqlite::Error::InvalidQuery)?,
                codex_domain::IdentityId::parse(&row.get::<_,String>(1)?).map_err(|_|rusqlite::Error::InvalidQuery)?,
                ContentHash::parse(&row.get::<_,String>(2)?).map_err(|_|rusqlite::Error::InvalidQuery)?,
                ContentHash::parse(&row.get::<_,String>(3)?).map_err(|_|rusqlite::Error::InvalidQuery)?,
                codex_domain::UnixMillis::new(row.get(4)?).map_err(|_|rusqlite::Error::InvalidQuery)?,
                codex_domain::UnixMillis::new(row.get(5)?).map_err(|_|rusqlite::Error::InvalidQuery)?,
                codex_domain::EntityVersion::new(row.get::<_,u64>(6)?).map_err(|_|rusqlite::Error::InvalidQuery)?,
            ).map_err(|_|rusqlite::Error::InvalidQuery)
        }).optional().map_err(|_|RepositoryError::corrupt_data())
    }
}

#[allow(dead_code)]
fn _assert_storage_mappings(kind: CredentialKind, mode: AuthMode, status: IdentityStatus) {
    let _ = (
        kind.as_storage_str(),
        mode.as_storage_str(),
        status.as_storage_str(),
    );
}
