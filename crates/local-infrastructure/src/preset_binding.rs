use codex_application::{
    CreatePresetAndBindCommand, PresetBindingEntity, PresetBindingOutcome, PresetBindingRepository,
    PresetBindingRepositoryError, PresetBindingSummary, UpdatePresetAndBindCommand,
};
use codex_domain::{EntityVersion, ModelPreset, RuntimeIdentity};
use rusqlite::{
    Error as SqlError, ErrorCode, OptionalExtension, Transaction, TransactionBehavior, params,
};

use crate::repository::{
    SqliteMetadataRepository, identity_from_row, identity_select, preset_from_row, preset_params,
    preset_select, version_to_i64,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresetBindingFaultPoint {
    AfterPresetWrite,
    BeforeIdentityWrite,
    AfterIdentityWrite,
    BeforeCommit,
    CommitOutcomeUnknown,
}

/// M2.7 专用故障注入边界；只允许在五个固定事务切点请求中断。
pub trait PresetBindingFaults {
    fn should_fail(&mut self, point: PresetBindingFaultPoint) -> bool;
}

#[derive(Default)]
pub struct NoPresetBindingFaults;

impl PresetBindingFaults for NoPresetBindingFaults {
    fn should_fail(&mut self, _: PresetBindingFaultPoint) -> bool {
        false
    }
}

impl SqliteMetadataRepository {
    pub fn create_preset_and_bind_with_faults<F: PresetBindingFaults>(
        &mut self,
        command: CreatePresetAndBindCommand,
        faults: &mut F,
    ) -> Result<PresetBindingOutcome, PresetBindingRepositoryError> {
        let transaction = begin_immediate(self)?;
        let identity = read_identity(&transaction, command.identity_id.as_str())?.ok_or(
            PresetBindingRepositoryError::NotFound(PresetBindingEntity::Identity),
        )?;
        let existing_preset = read_preset(&transaction, command.preset.id().as_str())?;

        if identity.version() != command.expected_identity_version {
            if create_was_already_applied(&identity, existing_preset.as_ref(), &command) {
                return Ok(PresetBindingOutcome::AlreadyApplied(summary(
                    &identity,
                    existing_preset.as_ref().expect("checked existing preset"),
                )));
            }
            return Err(PresetBindingRepositoryError::Conflict);
        }
        if existing_preset.is_some() {
            return Err(PresetBindingRepositoryError::Conflict);
        }

        transaction
            .execute(
                "INSERT INTO model_presets(
                    id,identity_id,name,model_id,created_at_unix_ms,updated_at_unix_ms,version
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7)",
                preset_params(&command.preset),
            )
            .map_err(map_write_error)?;
        fail_before_commit(faults, PresetBindingFaultPoint::AfterPresetWrite)?;
        fail_before_commit(faults, PresetBindingFaultPoint::BeforeIdentityWrite)?;

        let bound_identity = identity
            .set_default_preset(&command.preset, command.now)
            .map_err(|_| PresetBindingRepositoryError::Validation)?;
        cas_identity(
            &transaction,
            &bound_identity,
            command.expected_identity_version,
        )?;
        fail_before_commit(faults, PresetBindingFaultPoint::AfterIdentityWrite)?;
        fail_before_commit(faults, PresetBindingFaultPoint::BeforeCommit)?;

        transaction
            .commit()
            .map_err(|_| PresetBindingRepositoryError::RecoveryRequired)?;
        if faults.should_fail(PresetBindingFaultPoint::CommitOutcomeUnknown) {
            return Err(PresetBindingRepositoryError::RecoveryRequired);
        }
        Ok(PresetBindingOutcome::Applied(summary(
            &bound_identity,
            &command.preset,
        )))
    }

    pub fn update_preset_and_bind_with_faults<F: PresetBindingFaults>(
        &mut self,
        command: UpdatePresetAndBindCommand,
        faults: &mut F,
    ) -> Result<PresetBindingOutcome, PresetBindingRepositoryError> {
        let transaction = begin_immediate(self)?;
        let identity = read_identity(&transaction, command.identity_id.as_str())?.ok_or(
            PresetBindingRepositoryError::NotFound(PresetBindingEntity::Identity),
        )?;
        let preset = read_preset(&transaction, command.preset_id.as_str())?.ok_or(
            PresetBindingRepositoryError::NotFound(PresetBindingEntity::Preset),
        )?;

        if update_was_already_applied(&identity, &preset, &command) {
            return Ok(PresetBindingOutcome::AlreadyApplied(summary(
                &identity, &preset,
            )));
        }
        if identity.version() != command.expected_identity_version
            || preset.version() != command.expected_preset_version
            || preset.identity_id() != &command.identity_id
        {
            return Err(PresetBindingRepositoryError::Conflict);
        }

        let updated_preset = preset
            .update_metadata(command.name, command.model_id, command.now)
            .map_err(|_| PresetBindingRepositoryError::Validation)?;
        cas_preset(
            &transaction,
            &updated_preset,
            command.expected_preset_version,
        )?;
        fail_before_commit(faults, PresetBindingFaultPoint::AfterPresetWrite)?;
        fail_before_commit(faults, PresetBindingFaultPoint::BeforeIdentityWrite)?;

        let bound_identity = identity
            .set_default_preset(&updated_preset, command.now)
            .map_err(|_| PresetBindingRepositoryError::Validation)?;
        cas_identity(
            &transaction,
            &bound_identity,
            command.expected_identity_version,
        )?;
        fail_before_commit(faults, PresetBindingFaultPoint::AfterIdentityWrite)?;
        fail_before_commit(faults, PresetBindingFaultPoint::BeforeCommit)?;

        transaction
            .commit()
            .map_err(|_| PresetBindingRepositoryError::RecoveryRequired)?;
        if faults.should_fail(PresetBindingFaultPoint::CommitOutcomeUnknown) {
            return Err(PresetBindingRepositoryError::RecoveryRequired);
        }
        Ok(PresetBindingOutcome::Applied(summary(
            &bound_identity,
            &updated_preset,
        )))
    }
}

impl PresetBindingRepository for SqliteMetadataRepository {
    fn create_preset_and_bind(
        &mut self,
        command: CreatePresetAndBindCommand,
    ) -> Result<PresetBindingOutcome, PresetBindingRepositoryError> {
        self.create_preset_and_bind_with_faults(command, &mut NoPresetBindingFaults)
    }

    fn update_preset_and_bind(
        &mut self,
        command: UpdatePresetAndBindCommand,
    ) -> Result<PresetBindingOutcome, PresetBindingRepositoryError> {
        self.update_preset_and_bind_with_faults(command, &mut NoPresetBindingFaults)
    }
}

fn begin_immediate(
    repository: &mut SqliteMetadataRepository,
) -> Result<Transaction<'_>, PresetBindingRepositoryError> {
    repository
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_begin_error)
}

fn read_identity(
    transaction: &Transaction<'_>,
    id: &str,
) -> Result<Option<RuntimeIdentity>, PresetBindingRepositoryError> {
    transaction
        .query_row(
            &format!("{} WHERE id=?1", identity_select()),
            [id],
            identity_from_row,
        )
        .optional()
        .map_err(map_read_error)
}

fn read_preset(
    transaction: &Transaction<'_>,
    id: &str,
) -> Result<Option<ModelPreset>, PresetBindingRepositoryError> {
    transaction
        .query_row(
            &format!("{} WHERE id=?1", preset_select()),
            [id],
            preset_from_row,
        )
        .optional()
        .map_err(map_read_error)
}

fn cas_preset(
    transaction: &Transaction<'_>,
    preset: &ModelPreset,
    expected_preset_version: EntityVersion,
) -> Result<(), PresetBindingRepositoryError> {
    let changed = transaction
        .execute(
            "UPDATE model_presets SET name=?2,model_id=?3,updated_at_unix_ms=?4,version=?5
             WHERE id=?1 AND identity_id=?6 AND version=?7",
            params![
                preset.id().as_str(),
                preset.name().as_str(),
                preset.model_id().as_str(),
                preset.updated_at().value(),
                version_to_i64(preset.version()),
                preset.identity_id().as_str(),
                version_to_i64(expected_preset_version),
            ],
        )
        .map_err(map_write_error)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(PresetBindingRepositoryError::Conflict)
    }
}

fn cas_identity(
    transaction: &Transaction<'_>,
    identity: &RuntimeIdentity,
    expected_identity_version: EntityVersion,
) -> Result<(), PresetBindingRepositoryError> {
    let changed = transaction
        .execute(
            "UPDATE runtime_identities SET default_model_preset_id=?2,status=?3,
                    updated_at_unix_ms=?4,version=?5
             WHERE id=?1 AND version=?6",
            params![
                identity.id().as_str(),
                identity
                    .default_model_preset_id()
                    .map(|value| value.as_str()),
                identity.status().as_storage_str(),
                identity.updated_at().value(),
                version_to_i64(identity.version()),
                version_to_i64(expected_identity_version),
            ],
        )
        .map_err(map_write_error)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(PresetBindingRepositoryError::Conflict)
    }
}

fn create_was_already_applied(
    identity: &RuntimeIdentity,
    preset: Option<&ModelPreset>,
    command: &CreatePresetAndBindCommand,
) -> bool {
    let Some(preset) = preset else { return false };
    command.expected_identity_version.next().ok() == Some(identity.version())
        && identity.default_model_preset_id() == Some(preset.id())
        && preset == &command.preset
}

fn update_was_already_applied(
    identity: &RuntimeIdentity,
    preset: &ModelPreset,
    command: &UpdatePresetAndBindCommand,
) -> bool {
    command.expected_identity_version.next().ok() == Some(identity.version())
        && command.expected_preset_version.next().ok() == Some(preset.version())
        && identity.default_model_preset_id() == Some(preset.id())
        && preset.identity_id() == &command.identity_id
        && preset.name() == &command.name
        && preset.model_id() == &command.model_id
        && preset.updated_at() == command.now
}

fn summary(identity: &RuntimeIdentity, preset: &ModelPreset) -> PresetBindingSummary {
    PresetBindingSummary {
        identity_id: identity.id().clone(),
        identity_version: identity.version(),
        preset_id: preset.id().clone(),
        preset_name: preset.name().clone(),
        model_id: preset.model_id().clone(),
        preset_version: preset.version(),
    }
}

fn fail_before_commit<F: PresetBindingFaults>(
    faults: &mut F,
    point: PresetBindingFaultPoint,
) -> Result<(), PresetBindingRepositoryError> {
    if faults.should_fail(point) {
        Err(PresetBindingRepositoryError::StorageUnavailable)
    } else {
        Ok(())
    }
}

fn map_begin_error(error: SqlError) -> PresetBindingRepositoryError {
    if is_busy(&error) {
        PresetBindingRepositoryError::Conflict
    } else {
        PresetBindingRepositoryError::StorageUnavailable
    }
}

fn map_read_error(error: SqlError) -> PresetBindingRepositoryError {
    match error {
        SqlError::FromSqlConversionFailure(..) | SqlError::InvalidColumnType(..) => {
            PresetBindingRepositoryError::CorruptData
        }
        _ if is_busy(&error) => PresetBindingRepositoryError::Conflict,
        _ => PresetBindingRepositoryError::StorageUnavailable,
    }
}

fn map_write_error(error: SqlError) -> PresetBindingRepositoryError {
    match error {
        SqlError::SqliteFailure(details, _) if details.code == ErrorCode::ConstraintViolation => {
            PresetBindingRepositoryError::Conflict
        }
        _ if is_busy(&error) => PresetBindingRepositoryError::Conflict,
        _ => PresetBindingRepositoryError::StorageUnavailable,
    }
}

fn is_busy(error: &SqlError) -> bool {
    matches!(
        error,
        SqlError::SqliteFailure(details, _)
            if matches!(details.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}
