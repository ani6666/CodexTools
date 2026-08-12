use codex_application::{
    EntityKind, IdentityBundle, IdentityBundleRepository, ManagedConfigPatchRepository,
    RepositoryError,
};
use codex_domain::{
    AuthMode, ContentHash, CredentialKind, IdentityStatus, ManagedConfigPatch,
    ManagedConfigPatchId, ModelPresetId,
};
use rusqlite::{OptionalExtension, params};

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
