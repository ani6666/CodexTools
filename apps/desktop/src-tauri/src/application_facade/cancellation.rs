use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::SafeIdentifier;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationOutcome {
    Requested,
    AlreadyRequested,
    UnknownOperation,
    TooLate,
    AlreadyCompleted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationCheckpoint {
    Continue,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationRegistrationError {
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OperationState {
    Cancellable { requested: bool },
    NonCancellable,
    Completed,
}

#[derive(Debug, Default)]
pub struct OperationRegistry {
    operations: HashMap<SafeIdentifier, OperationState>,
}

impl OperationRegistry {
    pub fn register(
        &mut self,
        operation_id: SafeIdentifier,
    ) -> Result<(), OperationRegistrationError> {
        if self.operations.contains_key(&operation_id) {
            return Err(OperationRegistrationError::Conflict);
        }
        self.operations.insert(
            operation_id,
            OperationState::Cancellable { requested: false },
        );
        Ok(())
    }

    #[must_use]
    pub fn cancel(&mut self, operation_id: &SafeIdentifier) -> CancellationOutcome {
        match self.operations.get_mut(operation_id) {
            None => CancellationOutcome::UnknownOperation,
            Some(OperationState::Cancellable { requested }) if !*requested => {
                *requested = true;
                CancellationOutcome::Requested
            }
            Some(OperationState::Cancellable { .. }) => CancellationOutcome::AlreadyRequested,
            Some(OperationState::NonCancellable) => CancellationOutcome::TooLate,
            Some(OperationState::Completed) => CancellationOutcome::AlreadyCompleted,
        }
    }

    #[must_use]
    pub fn checkpoint(&self, operation_id: &SafeIdentifier) -> CancellationCheckpoint {
        match self.operations.get(operation_id) {
            Some(OperationState::Cancellable { requested: true }) => {
                CancellationCheckpoint::Cancelled
            }
            _ => CancellationCheckpoint::Continue,
        }
    }

    pub fn enter_non_cancellable(
        &mut self,
        operation_id: &SafeIdentifier,
    ) -> Result<(), CancellationCheckpoint> {
        match self.operations.get_mut(operation_id) {
            Some(OperationState::Cancellable { requested: true }) => {
                Err(CancellationCheckpoint::Cancelled)
            }
            Some(state @ OperationState::Cancellable { requested: false }) => {
                *state = OperationState::NonCancellable;
                Ok(())
            }
            Some(OperationState::NonCancellable | OperationState::Completed) | None => {
                Err(CancellationCheckpoint::Continue)
            }
        }
    }

    pub fn complete(&mut self, operation_id: &SafeIdentifier) -> bool {
        match self.operations.get_mut(operation_id) {
            Some(state) => {
                *state = OperationState::Completed;
                true
            }
            None => false,
        }
    }

    /// 仅回滚尚未取消、尚未进入原子临界区的注册；临界区和完成态不会被删除。
    pub fn rollback_registration(&mut self, operation_id: &SafeIdentifier) -> bool {
        match self.operations.get(operation_id) {
            Some(OperationState::Cancellable { requested: false }) => {
                self.operations.remove(operation_id).is_some()
            }
            _ => false,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// 显式释放完成态，避免长生命周期进程无限保留 operation id。
    pub fn remove_completed(&mut self, operation_id: &SafeIdentifier) -> bool {
        if matches!(
            self.operations.get(operation_id),
            Some(OperationState::Completed)
        ) {
            self.operations.remove(operation_id).is_some()
        } else {
            false
        }
    }
}
