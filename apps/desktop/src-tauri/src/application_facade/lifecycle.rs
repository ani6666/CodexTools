use std::{
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

use super::{ErrorCode, ErrorEnvelope};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessLifecyclePhase {
    Accepting,
    Draining,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessLifecycleSnapshot {
    pub phase: ProcessLifecyclePhase,
    pub active: usize,
    pub exit_attempt_active: bool,
}

#[derive(Debug)]
struct LifecycleState {
    phase: ProcessLifecyclePhase,
    active: usize,
    exit_attempt_active: bool,
}

#[derive(Debug)]
struct LifecycleInner {
    state: Mutex<LifecycleState>,
    changed: Condvar,
}

#[derive(Clone, Debug)]
pub struct ProcessLifecycleGate {
    inner: Arc<LifecycleInner>,
}

impl Default for ProcessLifecycleGate {
    fn default() -> Self {
        Self {
            inner: Arc::new(LifecycleInner {
                state: Mutex::new(LifecycleState {
                    phase: ProcessLifecyclePhase::Accepting,
                    active: 0,
                    exit_attempt_active: false,
                }),
                changed: Condvar::new(),
            }),
        }
    }
}

impl ProcessLifecycleGate {
    pub fn try_admit(&self) -> Result<ProcessAdmissionLease, ErrorEnvelope> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| ErrorEnvelope::from_code(ErrorCode::Internal))?;
        if state.phase != ProcessLifecyclePhase::Accepting {
            return Err(ErrorEnvelope::from_code(ErrorCode::ExitInProgress));
        }
        state.active = state
            .active
            .checked_add(1)
            .ok_or_else(|| ErrorEnvelope::from_code(ErrorCode::Internal))?;
        Ok(ProcessAdmissionLease {
            inner: Arc::clone(&self.inner),
            released: false,
        })
    }

    pub fn begin_exit(&self) -> Result<ProcessExitPermit, ErrorEnvelope> {
        let mut state = self
            .inner
            .state
            .lock()
            .map_err(|_| ErrorEnvelope::from_code(ErrorCode::Internal))?;
        if state.exit_attempt_active {
            return Err(ErrorEnvelope::from_code(ErrorCode::Conflict));
        }
        state.phase = ProcessLifecyclePhase::Draining;
        state.exit_attempt_active = true;
        self.inner.changed.notify_all();
        Ok(ProcessExitPermit {
            inner: Arc::clone(&self.inner),
            released: false,
        })
    }

    pub fn snapshot(&self) -> Result<ProcessLifecycleSnapshot, ErrorEnvelope> {
        let state = self
            .inner
            .state
            .lock()
            .map_err(|_| ErrorEnvelope::from_code(ErrorCode::Internal))?;
        Ok(ProcessLifecycleSnapshot {
            phase: state.phase,
            active: state.active,
            exit_attempt_active: state.exit_attempt_active,
        })
    }

    pub fn wait_for_phase(&self, phase: ProcessLifecyclePhase, timeout: Duration) -> bool {
        let Ok(state) = self.inner.state.lock() else {
            return false;
        };
        let Ok((state, _)) = self
            .inner
            .changed
            .wait_timeout_while(state, timeout, |current| current.phase != phase)
        else {
            return false;
        };
        state.phase == phase
    }

    pub fn wait_for_exit_attempt(&self, timeout: Duration) -> bool {
        let Ok(state) = self.inner.state.lock() else {
            return false;
        };
        let Ok((state, _)) = self
            .inner
            .changed
            .wait_timeout_while(state, timeout, |current| !current.exit_attempt_active)
        else {
            return false;
        };
        state.exit_attempt_active
    }
}

#[derive(Debug)]
pub struct ProcessAdmissionLease {
    inner: Arc<LifecycleInner>,
    released: bool,
}

impl Drop for ProcessAdmissionLease {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        if let Ok(mut state) = self.inner.state.lock() {
            state.active = state.active.saturating_sub(1);
            self.released = true;
            self.inner.changed.notify_all();
        }
    }
}

#[derive(Debug)]
pub struct ProcessExitPermit {
    inner: Arc<LifecycleInner>,
    released: bool,
}

impl ProcessExitPermit {
    pub fn wait_for_zero(&self, timeout: Duration) -> Result<bool, ErrorEnvelope> {
        let state = self
            .inner
            .state
            .lock()
            .map_err(|_| ErrorEnvelope::from_code(ErrorCode::Internal))?;
        let (state, _) = self
            .inner
            .changed
            .wait_timeout_while(state, timeout, |current| current.active != 0)
            .map_err(|_| ErrorEnvelope::from_code(ErrorCode::Internal))?;
        Ok(state.active == 0)
    }
}

impl Drop for ProcessExitPermit {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        if let Ok(mut state) = self.inner.state.lock() {
            state.exit_attempt_active = false;
            self.released = true;
            self.inner.changed.notify_all();
        }
    }
}
