use std::{fmt, path::Path, time::Duration};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthProcessOutcome {
    Succeeded,
    Cancelled,
    TimedOut,
    ExitedUnsuccessfully,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthCaptureError {
    Cancelled,
    TimedOut,
    ProcessFailed,
    ProcessTreeUnconfirmed,
    MissingAuthentication,
    CompatibilityProtected,
    OutsideWriteDetected,
    CredentialFailure,
    IoFailure,
}

impl fmt::Display for OAuthCaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Cancelled => "OAuth capture was cancelled",
            Self::TimedOut => "OAuth capture timed out",
            Self::ProcessFailed => "OAuth helper failed",
            Self::ProcessTreeUnconfirmed => "OAuth helper process tree termination is unconfirmed",
            Self::MissingAuthentication => "OAuth authentication material was not produced",
            Self::CompatibilityProtected => "OAuth authentication shape is not supported",
            Self::OutsideWriteDetected => "OAuth helper wrote outside its isolated directory",
            Self::CredentialFailure => "OAuth credential persistence failed",
            Self::IoFailure => "OAuth capture storage failed",
        })
    }
}
impl std::error::Error for OAuthCaptureError {}

pub trait OAuthProcessRunner {
    fn run(
        &mut self,
        executable: &Path,
        capture_root: &Path,
        audit_root: &Path,
        mode: &str,
        timeout: Duration,
    ) -> Result<OAuthProcessOutcome, OAuthCaptureError>;
}
