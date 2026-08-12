use std::{
    fmt,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
};

use codex_adapter::hash_bytes;
use codex_application::{
    BoundSecretConsumer, CredentialEnvelopeBinding, CredentialMaterialDiagnostic,
    CredentialRecoveryOperation, CredentialRecoveryPhase, CredentialRecoveryRecord,
    CredentialRecoveryRepository, CredentialReferenceRepository, CredentialStore,
    CredentialStoreError, RepositoryError, SecretConsumer,
};
use codex_domain::{
    CredentialBackend, CredentialFingerprint, CredentialKind, CredentialRefId, CredentialReference,
    EntityVersion, SchemaFingerprint, UnixMillis,
};
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialServiceError {
    AlreadyExists,
    NotFound,
    VersionConflict,
    ReferenceConflict,
    InvalidSecret,
    StoreFailure,
    RepositoryFailure,
    RecoveryRequired,
}

impl fmt::Display for CredentialServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AlreadyExists => "credential already exists",
            Self::NotFound => "credential was not found",
            Self::VersionConflict => "credential version conflict",
            Self::ReferenceConflict => "credential is still referenced",
            Self::InvalidSecret => "credential input is invalid",
            Self::StoreFailure => "credential store operation failed",
            Self::RepositoryFailure => "credential metadata operation failed",
            Self::RecoveryRequired => "credential recovery is required",
        })
    }
}
impl std::error::Error for CredentialServiceError {}

pub struct CredentialService<'a, R, S> {
    repository: &'a mut R,
    store: &'a mut S,
}

impl<'a, R, S> CredentialService<'a, R, S>
where
    R: CredentialReferenceRepository + CredentialRecoveryRepository,
    S: CredentialStore,
{
    pub const fn new(repository: &'a mut R, store: &'a mut S) -> Self {
        Self { repository, store }
    }

    pub fn create_api_key(
        &mut self,
        id: CredentialRefId,
        secret: &mut [u8],
        now: UnixMillis,
    ) -> Result<CredentialReference, CredentialServiceError> {
        self.create(id, CredentialKind::ApiKey, secret, now)
    }

    pub fn create_oauth_bundle(
        &mut self,
        id: CredentialRefId,
        secret: &mut [u8],
        now: UnixMillis,
    ) -> Result<CredentialReference, CredentialServiceError> {
        self.create(id, CredentialKind::OAuthBundle, secret, now)
    }

    fn create(
        &mut self,
        id: CredentialRefId,
        kind: CredentialKind,
        secret: &mut [u8],
        now: UnixMillis,
    ) -> Result<CredentialReference, CredentialServiceError> {
        let owner = match self.store.begin_mutation(&id) {
            Ok(owner) => owner,
            Err(error) => {
                secret.zeroize();
                return Err(map_store_error(error));
            }
        };
        let result = (|| {
            validate_secret(kind, secret)?;
            let schema = schema_fingerprint(kind);
            let fingerprint = credential_fingerprint(secret);
            let reference = CredentialReference::new(
                id,
                kind,
                CredentialBackend::WindowsDpapiCurrentUser,
                schema.clone(),
                fingerprint,
                now,
            );
            let reference = self.reference_with_recovery_timestamps(
                reference,
                CredentialRecoveryOperation::Create,
            )?;
            let binding = binding(&reference);
            if let Some(existing) = self
                .repository
                .get_credential_reference(reference.id())
                .map_err(map_repository_error)?
            {
                if same_reference_material(&existing, &reference) {
                    self.clear_matching_recovery(
                        reference.id(),
                        CredentialRecoveryOperation::Create,
                        reference.version(),
                    )?;
                    return Ok(existing);
                }
                return Err(CredentialServiceError::AlreadyExists);
            }
            let recovery = self.ensure_prepared_recovery(
                &reference,
                CredentialRecoveryOperation::Create,
                now,
            )?;
            match self.store.create(&binding, secret) {
                Ok(()) => {}
                Err(CredentialStoreError::AlreadyExists) => {
                    if self.material_fingerprint(&binding)? != *reference.credential_fingerprint() {
                        return Err(CredentialServiceError::RecoveryRequired);
                    }
                }
                Err(error) => {
                    if error == CredentialStoreError::RecoveryRequired {
                        self.mark_recovery_required(recovery, "credential_material_create", now)?;
                        return Err(CredentialServiceError::RecoveryRequired);
                    }
                    let mapped = map_store_error(error);
                    if self.clear_recovery(recovery.clone()).is_err() {
                        return Err(CredentialServiceError::RecoveryRequired);
                    }
                    return Err(mapped);
                }
            }
            let material = self
                .store
                .inspect(&binding)
                .map_err(|_| CredentialServiceError::RecoveryRequired)?;
            let recovery = self.publish_recovery(recovery, material, now)?;
            if self
                .repository
                .create_credential_reference(&reference)
                .is_err()
            {
                self.mark_recovery_required(recovery, "credential_metadata_create", now)?;
                return Err(CredentialServiceError::RecoveryRequired);
            }
            self.clear_recovery(recovery)?;
            Ok(reference)
        })();
        let released = self.store.end_mutation(owner);
        secret.zeroize();
        if released.is_err() {
            Err(CredentialServiceError::RecoveryRequired)
        } else {
            result
        }
    }

    pub fn rotate_credential(
        &mut self,
        id: &CredentialRefId,
        expected_version: EntityVersion,
        secret: &mut [u8],
        now: UnixMillis,
    ) -> Result<CredentialReference, CredentialServiceError> {
        let owner = match self.store.begin_mutation(id) {
            Ok(owner) => owner,
            Err(error) => {
                secret.zeroize();
                return Err(map_store_error(error));
            }
        };
        let result = (|| {
            let current = self
                .repository
                .get_credential_reference(id)
                .map_err(map_repository_error)?
                .ok_or(CredentialServiceError::NotFound)?;
            if current.version() != expected_version {
                validate_secret(current.kind(), secret)?;
                let fingerprint = credential_fingerprint(secret);
                if current.version().value() == expected_version.value() + 1
                    && current.credential_fingerprint() == &fingerprint
                {
                    let current_binding = binding(&current);
                    if self.material_fingerprint(&current_binding)? != fingerprint {
                        return Err(CredentialServiceError::RecoveryRequired);
                    }
                    self.clear_matching_recovery(
                        current.id(),
                        CredentialRecoveryOperation::Rotate,
                        current.version(),
                    )?;
                    return Ok(current);
                }
                return Err(CredentialServiceError::VersionConflict);
            }
            validate_secret(current.kind(), secret)?;
            let next = current
                .rotate(
                    schema_fingerprint(current.kind()),
                    credential_fingerprint(secret),
                    now,
                )
                .map_err(|_| CredentialServiceError::VersionConflict)?;
            let next =
                self.reference_with_recovery_timestamps(next, CredentialRecoveryOperation::Rotate)?;
            let previous_binding = binding(&current);
            let next_binding = binding(&next);
            let recovery =
                self.ensure_prepared_recovery(&next, CredentialRecoveryOperation::Rotate, now)?;
            match self.store.rotate(&previous_binding, &next_binding, secret) {
                Ok(()) => {}
                Err(CredentialStoreError::VersionConflict) => {
                    if self.material_fingerprint(&next_binding)? != *next.credential_fingerprint() {
                        return Err(CredentialServiceError::RecoveryRequired);
                    }
                }
                Err(error) => {
                    if error == CredentialStoreError::RecoveryRequired {
                        self.mark_recovery_required(recovery, "credential_material_rotate", now)?;
                        return Err(CredentialServiceError::RecoveryRequired);
                    }
                    let mapped = map_store_error(error);
                    if self.clear_recovery(recovery.clone()).is_err() {
                        return Err(CredentialServiceError::RecoveryRequired);
                    }
                    return Err(mapped);
                }
            }
            let material = self
                .store
                .inspect(&next_binding)
                .map_err(|_| CredentialServiceError::RecoveryRequired)?;
            let recovery = self.publish_recovery(recovery, material, now)?;
            if self
                .repository
                .update_credential_reference(&next, expected_version)
                .is_err()
            {
                self.mark_recovery_required(recovery, "credential_metadata_rotate", now)?;
                return Err(CredentialServiceError::RecoveryRequired);
            }
            self.clear_recovery(recovery)?;
            Ok(next)
        })();
        let released = self.store.end_mutation(owner);
        secret.zeroize();
        if released.is_err() {
            Err(CredentialServiceError::RecoveryRequired)
        } else {
            result
        }
    }

    pub fn read_for_switch(
        &mut self,
        id: &CredentialRefId,
        consumer: &mut dyn SecretConsumer,
    ) -> Result<CredentialReference, CredentialServiceError> {
        let owner = self.store.begin_mutation(id).map_err(map_store_error)?;
        let mut consumer_panic = None;
        let result = (|| {
            let reference = self
                .repository
                .get_credential_reference(id)
                .map_err(map_repository_error)?
                .ok_or(CredentialServiceError::NotFound)?;
            let mut buffered = BufferedSecret::default();
            self.store
                .read(&binding(&reference), &mut buffered)
                .map_err(map_store_error)?;
            let exact = self
                .repository
                .get_credential_reference(id)
                .map_err(map_repository_error)?
                .ok_or(CredentialServiceError::RecoveryRequired)?;
            if exact != reference {
                return Err(CredentialServiceError::VersionConflict);
            }
            match catch_unwind(AssertUnwindSafe(|| consumer.consume(&buffered.bytes))) {
                Ok(result) => result.map_err(map_store_error)?,
                Err(payload) => {
                    consumer_panic = Some(payload);
                    return Err(CredentialServiceError::RecoveryRequired);
                }
            }
            Ok(reference)
        })();
        let released = self.store.end_mutation(owner);
        if let Some(payload) = consumer_panic {
            resume_unwind(payload);
        }
        if released.is_err() {
            Err(CredentialServiceError::RecoveryRequired)
        } else {
            result
        }
    }

    /// 在同一个跨进程 owner 临界区内完成 metadata→Store→metadata exact 复读，
    /// 然后把精确引用与明文一并交给纵向切换 consumer。
    pub fn read_bound_for_switch(
        &mut self,
        id: &CredentialRefId,
        consumer: &mut dyn BoundSecretConsumer,
    ) -> Result<CredentialReference, CredentialServiceError> {
        let owner = self.store.begin_mutation(id).map_err(map_store_error)?;
        let mut consumer_panic = None;
        let result = (|| {
            let reference = self
                .repository
                .get_credential_reference(id)
                .map_err(map_repository_error)?
                .ok_or(CredentialServiceError::NotFound)?;
            let mut buffered = BufferedSecret::default();
            self.store
                .read(&binding(&reference), &mut buffered)
                .map_err(map_store_error)?;
            let exact = self
                .repository
                .get_credential_reference(id)
                .map_err(map_repository_error)?
                .ok_or(CredentialServiceError::RecoveryRequired)?;
            if exact != reference {
                return Err(CredentialServiceError::VersionConflict);
            }
            match catch_unwind(AssertUnwindSafe(|| {
                consumer.consume(&exact, &buffered.bytes)
            })) {
                Ok(result) => result.map_err(map_store_error)?,
                Err(payload) => {
                    consumer_panic = Some(payload);
                    return Err(CredentialServiceError::RecoveryRequired);
                }
            }
            Ok(exact)
        })();
        let released = self.store.end_mutation(owner);
        if let Some(payload) = consumer_panic {
            resume_unwind(payload);
        }
        if released.is_err() {
            Err(CredentialServiceError::RecoveryRequired)
        } else {
            result
        }
    }

    pub fn delete_credential(
        &mut self,
        id: &CredentialRefId,
        expected_version: EntityVersion,
    ) -> Result<(), CredentialServiceError> {
        let owner = self.store.begin_mutation(id).map_err(map_store_error)?;
        let result = (|| {
            let reference = self
                .repository
                .get_credential_reference(id)
                .map_err(map_repository_error)?
                .ok_or(CredentialServiceError::NotFound)?;
            if reference.version() != expected_version {
                return Err(CredentialServiceError::VersionConflict);
            }
            let material = self
                .store
                .inspect(&binding(&reference))
                .map_err(|_| CredentialServiceError::RecoveryRequired)?;
            let recovery = self
                .ensure_recovery(
                    &reference,
                    CredentialRecoveryOperation::Delete,
                    CredentialRecoveryPhase::DeletePending,
                    material,
                    reference.updated_at(),
                )
                .map_err(|_| CredentialServiceError::RecoveryRequired)?;
            if let Err(error) = self
                .repository
                .delete_credential_reference(id, expected_version)
            {
                self.clear_recovery(recovery)?;
                return Err(map_repository_error(error));
            }
            match self.store.delete(&binding(&reference)) {
                Ok(()) => self.clear_recovery(recovery),
                Err(_) => {
                    self.mark_recovery_required(
                        recovery,
                        "credential_material_delete",
                        reference.updated_at(),
                    )?;
                    Err(CredentialServiceError::RecoveryRequired)
                }
            }
        })();
        if self.store.end_mutation(owner).is_err() {
            Err(CredentialServiceError::RecoveryRequired)
        } else {
            result
        }
    }

    pub fn list_recovery_diagnostics(
        &self,
        id: &CredentialRefId,
    ) -> Result<Vec<CredentialRecoveryRecord>, CredentialServiceError> {
        self.repository
            .list_credential_recoveries(id)
            .map_err(map_repository_error)
    }

    pub fn adopt_recovery(
        &mut self,
        operation_id: &str,
        now: UnixMillis,
    ) -> Result<CredentialReference, CredentialServiceError> {
        let initial = self.load_recovery(operation_id)?;
        let owner = self
            .store
            .begin_mutation(&initial.credential_id)
            .map_err(map_store_error)?;
        let result = self.adopt_recovery_locked(operation_id, now);
        if self.store.end_mutation(owner).is_err() {
            Err(CredentialServiceError::RecoveryRequired)
        } else {
            result
        }
    }

    fn adopt_recovery_locked(
        &mut self,
        operation_id: &str,
        now: UnixMillis,
    ) -> Result<CredentialReference, CredentialServiceError> {
        let mut recovery = self.load_recovery(operation_id)?;
        let binding = recovery_binding(&recovery);
        let material = if recovery.operation == CredentialRecoveryOperation::Delete {
            self.store
                .inspect_delete_recovery(&binding)
                .map_err(map_store_error)?
        } else {
            self.store.inspect(&binding).map_err(map_store_error)?
        };
        if recovery.phase == CredentialRecoveryPhase::Prepared {
            recovery = self.publish_recovery(recovery, material, now)?;
        } else {
            ensure_same_material(&recovery, &material)?;
        }
        if recovery.operation == CredentialRecoveryOperation::Delete {
            self.store
                .restore_delete_recovery(&binding)
                .map_err(map_store_error)?;
        }
        let fingerprint = self.material_fingerprint(&binding)?;
        if recovery
            .planned_credential_fingerprint
            .as_ref()
            .is_some_and(|planned| planned != &fingerprint)
        {
            return Err(CredentialServiceError::RecoveryRequired);
        }
        let reference = match recovery.operation {
            CredentialRecoveryOperation::Create => CredentialReference::restore(
                recovery.credential_id.clone(),
                recovery.kind,
                CredentialBackend::WindowsDpapiCurrentUser,
                schema_fingerprint(recovery.kind),
                fingerprint,
                recovery.credential_created_at,
                recovery.credential_updated_at,
                recovery.generation,
            )
            .map_err(|_| CredentialServiceError::RecoveryRequired)?,
            CredentialRecoveryOperation::Rotate => {
                let expected = CredentialReference::restore(
                    recovery.credential_id.clone(),
                    recovery.kind,
                    CredentialBackend::WindowsDpapiCurrentUser,
                    schema_fingerprint(recovery.kind),
                    fingerprint,
                    recovery.credential_created_at,
                    recovery.credential_updated_at,
                    recovery.generation,
                )
                .map_err(|_| CredentialServiceError::RecoveryRequired)?;
                let current = self
                    .repository
                    .get_credential_reference(&recovery.credential_id)
                    .map_err(map_repository_error)?
                    .ok_or(CredentialServiceError::RecoveryRequired)?;
                if current.version() == recovery.generation {
                    if !same_reference_exact(&current, &expected) {
                        return Err(CredentialServiceError::RecoveryRequired);
                    }
                    self.clear_recovery(recovery)?;
                    return Ok(current);
                }
                if !is_expected_rotate_predecessor(&current, &expected) {
                    return Err(CredentialServiceError::RecoveryRequired);
                }
                expected
            }
            CredentialRecoveryOperation::Delete => CredentialReference::restore(
                recovery.credential_id.clone(),
                recovery.kind,
                CredentialBackend::WindowsDpapiCurrentUser,
                schema_fingerprint(recovery.kind),
                fingerprint,
                recovery.credential_created_at,
                recovery.credential_updated_at,
                recovery.generation,
            )
            .map_err(|_| CredentialServiceError::RecoveryRequired)?,
        };
        match recovery.operation {
            CredentialRecoveryOperation::Rotate => self
                .repository
                .update_credential_reference(
                    &reference,
                    EntityVersion::new(recovery.generation.value() - 1)
                        .map_err(|_| CredentialServiceError::RecoveryRequired)?,
                )
                .map_err(map_repository_error)?,
            CredentialRecoveryOperation::Create | CredentialRecoveryOperation::Delete => {
                if let Some(existing) = self
                    .repository
                    .get_credential_reference(&recovery.credential_id)
                    .map_err(map_repository_error)?
                {
                    if !same_reference_exact(&existing, &reference) {
                        return Err(CredentialServiceError::RecoveryRequired);
                    }
                    self.clear_recovery(recovery)?;
                    return Ok(existing);
                }
                self.repository
                    .create_credential_reference(&reference)
                    .map_err(map_repository_error)?;
            }
        }
        self.clear_recovery(recovery)?;
        Ok(reference)
    }

    pub fn rollback_recovery(
        &mut self,
        operation_id: &str,
        now: UnixMillis,
    ) -> Result<(), CredentialServiceError> {
        let initial = self.load_recovery(operation_id)?;
        let owner = self
            .store
            .begin_mutation(&initial.credential_id)
            .map_err(map_store_error)?;
        let result = self.rollback_recovery_locked(operation_id, now);
        if self.store.end_mutation(owner).is_err() {
            Err(CredentialServiceError::RecoveryRequired)
        } else {
            result
        }
    }

    fn rollback_recovery_locked(
        &mut self,
        operation_id: &str,
        now: UnixMillis,
    ) -> Result<(), CredentialServiceError> {
        let mut recovery = self.load_recovery(operation_id)?;
        let binding = recovery_binding(&recovery);
        if recovery.phase == CredentialRecoveryPhase::Prepared {
            match self.store.inspect(&binding) {
                Ok(material) => recovery = self.publish_recovery(recovery, material, now)?,
                Err(CredentialStoreError::NotFound) => return self.clear_recovery(recovery),
                Err(error) => return Err(map_store_error(error)),
            }
        }
        match recovery.operation {
            CredentialRecoveryOperation::Create => {
                if self
                    .repository
                    .get_credential_reference(&recovery.credential_id)
                    .map_err(map_repository_error)?
                    .is_some()
                {
                    return Err(CredentialServiceError::RecoveryRequired);
                }
                match self.store.delete(&binding) {
                    Ok(()) | Err(CredentialStoreError::NotFound) => {}
                    Err(error) => return Err(map_store_error(error)),
                }
            }
            CredentialRecoveryOperation::Rotate => {
                let current = self
                    .repository
                    .get_credential_reference(&recovery.credential_id)
                    .map_err(map_repository_error)?
                    .ok_or(CredentialServiceError::RecoveryRequired)?;
                if current.version().value() + 1 != recovery.generation.value() {
                    return Err(CredentialServiceError::RecoveryRequired);
                }
                let previous = CredentialEnvelopeBinding::new(
                    recovery.credential_id.clone(),
                    recovery.kind,
                    schema_fingerprint(recovery.kind),
                    EntityVersion::new(recovery.generation.value() - 1)
                        .map_err(|_| CredentialServiceError::RecoveryRequired)?,
                );
                self.store
                    .rollback_rotation(&previous, &binding)
                    .map_err(map_store_error)?;
            }
            CredentialRecoveryOperation::Delete => {
                let _ = self.adopt_recovery_locked(operation_id, now)?;
                return Ok(());
            }
        }
        self.clear_recovery(recovery)
    }

    pub fn cleanup_recovery(&mut self, operation_id: &str) -> Result<(), CredentialServiceError> {
        let initial = self.load_recovery(operation_id)?;
        let owner = self
            .store
            .begin_mutation(&initial.credential_id)
            .map_err(map_store_error)?;
        let result = self.cleanup_recovery_locked(operation_id);
        if self.store.end_mutation(owner).is_err() {
            Err(CredentialServiceError::RecoveryRequired)
        } else {
            result
        }
    }

    fn cleanup_recovery_locked(
        &mut self,
        operation_id: &str,
    ) -> Result<(), CredentialServiceError> {
        let mut recovery = self.load_recovery(operation_id)?;
        let binding = recovery_binding(&recovery);
        if recovery.phase == CredentialRecoveryPhase::Prepared {
            match self.store.inspect(&binding) {
                Ok(material) => {
                    let updated_at = recovery.updated_at;
                    recovery = self.publish_recovery(recovery, material, updated_at)?
                }
                Err(CredentialStoreError::NotFound) => return self.clear_recovery(recovery),
                Err(error) => return Err(map_store_error(error)),
            }
        }
        match recovery.operation {
            CredentialRecoveryOperation::Rotate => {
                if let Some(current) = self
                    .repository
                    .get_credential_reference(&recovery.credential_id)
                    .map_err(map_repository_error)?
                {
                    if current.version() == recovery.generation {
                        let fingerprint = self.material_fingerprint(&binding)?;
                        if current.credential_fingerprint() != &fingerprint {
                            return Err(CredentialServiceError::RecoveryRequired);
                        }
                        return self.clear_recovery(recovery);
                    }
                    if current.version().value() + 1 != recovery.generation.value() {
                        return Err(CredentialServiceError::RecoveryRequired);
                    }
                } else {
                    return Err(CredentialServiceError::RecoveryRequired);
                }
                let previous = CredentialEnvelopeBinding::new(
                    recovery.credential_id.clone(),
                    recovery.kind,
                    schema_fingerprint(recovery.kind),
                    EntityVersion::new(recovery.generation.value() - 1)
                        .map_err(|_| CredentialServiceError::RecoveryRequired)?,
                );
                self.store
                    .rollback_rotation(&previous, &binding)
                    .map_err(map_store_error)?;
            }
            CredentialRecoveryOperation::Create | CredentialRecoveryOperation::Delete => {
                if let Some(current) = self
                    .repository
                    .get_credential_reference(&recovery.credential_id)
                    .map_err(map_repository_error)?
                {
                    let fingerprint = self.material_fingerprint(&binding)?;
                    if current.version() != recovery.generation
                        || current.kind() != recovery.kind
                        || current.credential_fingerprint() != &fingerprint
                    {
                        return Err(CredentialServiceError::RecoveryRequired);
                    }
                    return self.clear_recovery(recovery);
                }
                match self.store.delete(&binding) {
                    Ok(()) | Err(CredentialStoreError::NotFound) => {}
                    Err(error) => return Err(map_store_error(error)),
                }
            }
        }
        self.clear_recovery(recovery)
    }

    fn material_fingerprint(
        &self,
        binding: &CredentialEnvelopeBinding,
    ) -> Result<CredentialFingerprint, CredentialServiceError> {
        let mut consumer = FingerprintConsumer { fingerprint: None };
        self.store
            .read(binding, &mut consumer)
            .map_err(map_store_error)?;
        consumer
            .fingerprint
            .ok_or(CredentialServiceError::RecoveryRequired)
    }

    fn ensure_recovery(
        &mut self,
        reference: &CredentialReference,
        operation: CredentialRecoveryOperation,
        phase: CredentialRecoveryPhase,
        material: CredentialMaterialDiagnostic,
        now: UnixMillis,
    ) -> Result<CredentialRecoveryRecord, CredentialServiceError> {
        let operation_id = recovery_operation_id(reference.id(), operation, reference.version());
        if let Some(existing) = self
            .repository
            .get_credential_recovery(&operation_id)
            .map_err(map_repository_error)?
        {
            if existing.credential_id != *reference.id()
                || existing.kind != reference.kind()
                || existing.operation != operation
                || existing.generation != reference.version()
                || existing.planned_credential_fingerprint.as_ref()
                    != Some(reference.credential_fingerprint())
                || existing.material_ref != material.material_ref
                || existing.material_hash.as_ref() != Some(&material.material_hash)
                || existing.credential_created_at != reference.created_at()
                || existing.credential_updated_at != reference.updated_at()
            {
                return Err(CredentialServiceError::RecoveryRequired);
            }
            return Ok(existing);
        }
        let record = CredentialRecoveryRecord {
            operation_id,
            credential_id: reference.id().clone(),
            kind: reference.kind(),
            operation,
            generation: reference.version(),
            planned_credential_fingerprint: Some(reference.credential_fingerprint().clone()),
            material_ref: material.material_ref,
            material_hash: Some(material.material_hash),
            phase,
            diagnostic_code: None,
            credential_created_at: reference.created_at(),
            credential_updated_at: reference.updated_at(),
            created_at: now,
            updated_at: now,
            version: EntityVersion::initial(),
        };
        self.repository
            .create_credential_recovery(&record)
            .map_err(map_repository_error)?;
        Ok(record)
    }

    fn reference_with_recovery_timestamps(
        &self,
        reference: CredentialReference,
        operation: CredentialRecoveryOperation,
    ) -> Result<CredentialReference, CredentialServiceError> {
        let operation_id = recovery_operation_id(reference.id(), operation, reference.version());
        let Some(existing) = self
            .repository
            .get_credential_recovery(&operation_id)
            .map_err(map_repository_error)?
        else {
            return Ok(reference);
        };
        if existing.credential_id != *reference.id()
            || existing.kind != reference.kind()
            || existing.operation != operation
            || existing.generation != reference.version()
        {
            return Err(CredentialServiceError::RecoveryRequired);
        }
        CredentialReference::restore(
            reference.id().clone(),
            reference.kind(),
            reference.backend(),
            reference.schema_fingerprint().clone(),
            reference.credential_fingerprint().clone(),
            existing.credential_created_at,
            existing.credential_updated_at,
            reference.version(),
        )
        .map_err(|_| CredentialServiceError::RecoveryRequired)
    }

    fn ensure_prepared_recovery(
        &mut self,
        reference: &CredentialReference,
        operation: CredentialRecoveryOperation,
        now: UnixMillis,
    ) -> Result<CredentialRecoveryRecord, CredentialServiceError> {
        let operation_id = recovery_operation_id(reference.id(), operation, reference.version());
        let material_ref = self
            .store
            .planned_material_ref(&binding(reference))
            .map_err(map_store_error)?;
        if let Some(existing) = self
            .repository
            .get_credential_recovery(&operation_id)
            .map_err(map_repository_error)?
        {
            if existing.credential_id != *reference.id()
                || existing.kind != reference.kind()
                || existing.operation != operation
                || existing.generation != reference.version()
                || existing.planned_credential_fingerprint.as_ref()
                    != Some(reference.credential_fingerprint())
                || existing.material_ref != material_ref
                || existing.credential_created_at != reference.created_at()
                || existing.credential_updated_at != reference.updated_at()
            {
                return Err(CredentialServiceError::RecoveryRequired);
            }
            return Ok(existing);
        }
        let record = CredentialRecoveryRecord {
            operation_id,
            credential_id: reference.id().clone(),
            kind: reference.kind(),
            operation,
            generation: reference.version(),
            planned_credential_fingerprint: Some(reference.credential_fingerprint().clone()),
            material_ref,
            material_hash: None,
            phase: CredentialRecoveryPhase::Prepared,
            diagnostic_code: Some("material_publish_pending".to_owned()),
            credential_created_at: reference.created_at(),
            credential_updated_at: reference.updated_at(),
            created_at: now,
            updated_at: now,
            version: EntityVersion::initial(),
        };
        self.repository
            .create_credential_recovery(&record)
            .map_err(map_repository_error)?;
        Ok(record)
    }

    fn publish_recovery(
        &mut self,
        mut record: CredentialRecoveryRecord,
        material: CredentialMaterialDiagnostic,
        now: UnixMillis,
    ) -> Result<CredentialRecoveryRecord, CredentialServiceError> {
        if let Some(existing_hash) = &record.material_hash {
            if record.material_ref == material.material_ref
                && existing_hash == &material.material_hash
            {
                return Ok(record);
            }
            return Err(CredentialServiceError::RecoveryRequired);
        }
        if record.phase != CredentialRecoveryPhase::Prepared
            || record.material_ref != material.material_ref
        {
            return Err(CredentialServiceError::RecoveryRequired);
        }
        let previous = record.version;
        record.material_hash = Some(material.material_hash);
        record.phase = CredentialRecoveryPhase::Published;
        record.diagnostic_code = None;
        record.updated_at = now;
        record.version = previous
            .next()
            .map_err(|_| CredentialServiceError::RecoveryRequired)?;
        self.repository
            .update_credential_recovery(&record, previous)
            .map_err(|_| CredentialServiceError::RecoveryRequired)?;
        Ok(record)
    }

    fn mark_recovery_required(
        &mut self,
        mut record: CredentialRecoveryRecord,
        diagnostic_code: &str,
        now: UnixMillis,
    ) -> Result<(), CredentialServiceError> {
        let previous = record.version;
        record.phase = CredentialRecoveryPhase::RecoveryRequired;
        record.diagnostic_code = Some(diagnostic_code.to_owned());
        record.updated_at = now;
        record.version = previous
            .next()
            .map_err(|_| CredentialServiceError::RecoveryRequired)?;
        self.repository
            .update_credential_recovery(&record, previous)
            .map_err(|_| CredentialServiceError::RecoveryRequired)
    }

    fn clear_recovery(
        &mut self,
        record: CredentialRecoveryRecord,
    ) -> Result<(), CredentialServiceError> {
        self.repository
            .delete_credential_recovery(&record.operation_id, record.version)
            .map_err(|_| CredentialServiceError::RecoveryRequired)
    }

    fn clear_matching_recovery(
        &mut self,
        id: &CredentialRefId,
        operation: CredentialRecoveryOperation,
        generation: EntityVersion,
    ) -> Result<(), CredentialServiceError> {
        let operation_id = recovery_operation_id(id, operation, generation);
        if let Some(record) = self
            .repository
            .get_credential_recovery(&operation_id)
            .map_err(map_repository_error)?
        {
            self.clear_recovery(record)?;
        }
        Ok(())
    }

    fn load_recovery(
        &self,
        operation_id: &str,
    ) -> Result<CredentialRecoveryRecord, CredentialServiceError> {
        self.repository
            .get_credential_recovery(operation_id)
            .map_err(map_repository_error)?
            .ok_or(CredentialServiceError::NotFound)
    }
}

struct FingerprintConsumer {
    fingerprint: Option<CredentialFingerprint>,
}

#[derive(Default)]
struct BufferedSecret {
    bytes: Vec<u8>,
}
impl SecretConsumer for BufferedSecret {
    fn consume(&mut self, secret: &[u8]) -> Result<(), CredentialStoreError> {
        self.bytes.zeroize();
        self.bytes.extend_from_slice(secret);
        Ok(())
    }
}
impl Drop for BufferedSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
impl SecretConsumer for FingerprintConsumer {
    fn consume(&mut self, secret: &[u8]) -> Result<(), CredentialStoreError> {
        self.fingerprint = Some(credential_fingerprint(secret));
        Ok(())
    }
}

fn recovery_operation_id(
    id: &CredentialRefId,
    operation: CredentialRecoveryOperation,
    generation: EntityVersion,
) -> String {
    let operation = match operation {
        CredentialRecoveryOperation::Create => "create",
        CredentialRecoveryOperation::Rotate => "rotate",
        CredentialRecoveryOperation::Delete => "delete",
    };
    format!(
        "credential:{}:{operation}:{}",
        id.as_str(),
        generation.value()
    )
}

fn recovery_binding(record: &CredentialRecoveryRecord) -> CredentialEnvelopeBinding {
    CredentialEnvelopeBinding::new(
        record.credential_id.clone(),
        record.kind,
        schema_fingerprint(record.kind),
        record.generation,
    )
}

fn ensure_same_material(
    record: &CredentialRecoveryRecord,
    material: &CredentialMaterialDiagnostic,
) -> Result<(), CredentialServiceError> {
    if record.material_ref == material.material_ref
        && record.material_hash.as_ref() == Some(&material.material_hash)
    {
        Ok(())
    } else {
        Err(CredentialServiceError::RecoveryRequired)
    }
}

fn same_reference_material(left: &CredentialReference, right: &CredentialReference) -> bool {
    left.id() == right.id()
        && left.kind() == right.kind()
        && left.backend() == right.backend()
        && left.schema_fingerprint() == right.schema_fingerprint()
        && left.credential_fingerprint() == right.credential_fingerprint()
        && left.version() == right.version()
}

fn same_reference_exact(left: &CredentialReference, right: &CredentialReference) -> bool {
    same_reference_material(left, right)
        && left.created_at() == right.created_at()
        && left.updated_at() == right.updated_at()
}

fn is_expected_rotate_predecessor(
    current: &CredentialReference,
    expected: &CredentialReference,
) -> bool {
    current.id() == expected.id()
        && current.kind() == expected.kind()
        && current.backend() == expected.backend()
        && current.schema_fingerprint() == &schema_fingerprint(current.kind())
        && current.created_at() == expected.created_at()
        && current.updated_at() <= expected.updated_at()
        && current
            .version()
            .value()
            .checked_add(1)
            .is_some_and(|next| next == expected.version().value())
}

fn binding(reference: &CredentialReference) -> CredentialEnvelopeBinding {
    CredentialEnvelopeBinding::new(
        reference.id().clone(),
        reference.kind(),
        reference.schema_fingerprint().clone(),
        reference.version(),
    )
}

fn schema_fingerprint(kind: CredentialKind) -> SchemaFingerprint {
    SchemaFingerprint::parse(
        hash_bytes(format!("codextools:credential:v1:{}", kind.as_storage_str()).as_bytes())
            .as_str(),
    )
    .expect("SHA-256 is a valid schema fingerprint")
}

fn credential_fingerprint(secret: &[u8]) -> CredentialFingerprint {
    CredentialFingerprint::parse(hash_bytes(secret).as_str())
        .expect("SHA-256 is a valid credential fingerprint")
}

fn validate_secret(kind: CredentialKind, secret: &[u8]) -> Result<(), CredentialServiceError> {
    if secret.is_empty() || secret.len() > 1024 * 1024 {
        return Err(CredentialServiceError::InvalidSecret);
    }
    if kind == CredentialKind::ApiKey {
        let value =
            std::str::from_utf8(secret).map_err(|_| CredentialServiceError::InvalidSecret)?;
        let Some(opaque_tail) = value.strip_prefix("sk-") else {
            return Err(CredentialServiceError::InvalidSecret);
        };
        let distinct = opaque_tail.bytes().fold([false; 128], |mut seen, byte| {
            if byte.is_ascii() {
                seen[usize::from(byte)] = true;
            }
            seen
        });
        let distinct_count = distinct.into_iter().filter(|seen| *seen).count();
        if !(32..=4093).contains(&opaque_tail.len())
            || distinct_count < 16
            || opaque_tail
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))
        {
            return Err(CredentialServiceError::InvalidSecret);
        }
    }
    if kind == CredentialKind::OAuthBundle {
        let config = b"model = \"gpt-SAMPLE-1\"\nmodel_provider = \"sample\"\n[model_providers.sample]\nname = \"Sample\"\nbase_url = \"https://HOST/v1\"\n";
        match codex_adapter::CodexAdapter::new().scan_memory(config, secret) {
            codex_application::ScanStatus::Ready(state)
                if state.authentication.auth_mode == codex_domain::AuthMode::OAuth => {}
            _ => return Err(CredentialServiceError::InvalidSecret),
        }
    }
    Ok(())
}

fn map_store_error(error: CredentialStoreError) -> CredentialServiceError {
    match error {
        CredentialStoreError::AlreadyExists => CredentialServiceError::AlreadyExists,
        CredentialStoreError::NotFound => CredentialServiceError::NotFound,
        CredentialStoreError::VersionConflict => CredentialServiceError::VersionConflict,
        CredentialStoreError::RecoveryRequired => CredentialServiceError::RecoveryRequired,
        _ => CredentialServiceError::StoreFailure,
    }
}

fn map_repository_error(error: RepositoryError) -> CredentialServiceError {
    match error {
        RepositoryError::NotFound(_) => CredentialServiceError::NotFound,
        RepositoryError::AlreadyExists(_) => CredentialServiceError::AlreadyExists,
        RepositoryError::VersionConflict(_) => CredentialServiceError::VersionConflict,
        RepositoryError::ReferenceConflict(_) => CredentialServiceError::ReferenceConflict,
        _ => CredentialServiceError::RepositoryFailure,
    }
}
