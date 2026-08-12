use std::{ffi::OsString, io, path::Path, time::Duration};

#[cfg(windows)]
pub fn detach_std_child(child: std::process::Child) -> io::Result<()> {
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::Foundation::CloseHandle;

    let handle = child.into_raw_handle();
    if unsafe { CloseHandle(handle) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
pub fn detach_std_child(mut child: std::process::Child) -> io::Result<()> {
    child.kill()?;
    child.wait().map(|_| ())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobProcessExit {
    Exited(u32),
    TimedOut,
}

#[derive(Debug)]
pub struct JobProcessWaitError {
    source: io::Error,
    tree_terminated: bool,
}

impl JobProcessWaitError {
    fn new(source: io::Error, tree_terminated: bool) -> Self {
        Self {
            source,
            tree_terminated,
        }
    }

    pub const fn tree_terminated(&self) -> bool {
        self.tree_terminated
    }
}

impl std::fmt::Display for JobProcessWaitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for JobProcessWaitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[cfg(windows)]
pub struct WindowsJobProcess {
    job: windows_sys::Win32::Foundation::HANDLE,
    process: windows_sys::Win32::Foundation::HANDLE,
    tree_finished: bool,
}

#[cfg(windows)]
impl WindowsJobProcess {
    pub fn spawn(
        executable: &Path,
        arguments: &[OsString],
        environment: &[(OsString, OsString)],
    ) -> io::Result<Self> {
        use std::{mem::size_of, os::windows::ffi::OsStrExt, ptr};
        use windows_sys::Win32::{
            Foundation::CloseHandle,
            System::{
                JobObjects::{
                    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                    SetInformationJobObject, TerminateJobObject,
                },
                Threading::{
                    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
                    PROCESS_INFORMATION, ResumeThread, STARTUPINFOW, TerminateProcess,
                },
            },
        };

        let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            let error = io::Error::last_os_error();
            unsafe { CloseHandle(job) };
            return Err(error);
        }

        let application = executable
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let mut command_line = windows_command_line(executable, arguments);
        let environment = windows_environment_block(environment)?;
        let mut startup = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut process = PROCESS_INFORMATION::default();
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                environment.as_ptr().cast(),
                ptr::null(),
                &raw mut startup,
                &raw mut process,
            )
        };
        if created == 0 {
            let error = io::Error::last_os_error();
            unsafe { CloseHandle(job) };
            return Err(error);
        }

        let assigned = unsafe { AssignProcessToJobObject(job, process.hProcess) };
        if assigned == 0 {
            let error = io::Error::last_os_error();
            unsafe {
                TerminateProcess(process.hProcess, 0xE000_0001);
                CloseHandle(process.hThread);
                CloseHandle(process.hProcess);
                CloseHandle(job);
            }
            return Err(error);
        }
        let resumed = unsafe { ResumeThread(process.hThread) };
        unsafe { CloseHandle(process.hThread) };
        if resumed == u32::MAX {
            let error = io::Error::last_os_error();
            unsafe {
                TerminateJobObject(job, 0xE000_0002);
                CloseHandle(process.hProcess);
                CloseHandle(job);
            }
            return Err(error);
        }

        Ok(Self {
            job,
            process: process.hProcess,
            tree_finished: false,
        })
    }

    pub fn wait(mut self, timeout: Duration) -> Result<JobProcessExit, JobProcessWaitError> {
        use std::time::Instant;
        use windows_sys::Win32::{
            Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
            System::{
                JobObjects::TerminateJobObject,
                Threading::{GetExitCodeProcess, WaitForSingleObject},
            },
        };

        let started = Instant::now();
        loop {
            let remaining = timeout.saturating_sub(started.elapsed());
            let wait_ms = remaining.as_millis().min(10) as u32;
            let result = unsafe { WaitForSingleObject(self.process, wait_ms) };
            if result == WAIT_OBJECT_0 {
                let mut exit_code = 0_u32;
                if unsafe { GetExitCodeProcess(self.process, &raw mut exit_code) } == 0 {
                    let error = io::Error::last_os_error();
                    let terminated = self.terminate_tree(0xE000_0003).is_ok();
                    return Err(JobProcessWaitError::new(error, terminated));
                }
                self.terminate_tree(0xE000_0004)
                    .map_err(|error| JobProcessWaitError::new(error, false))?;
                return Ok(JobProcessExit::Exited(exit_code));
            }
            if result != WAIT_TIMEOUT {
                let error = io::Error::last_os_error();
                let terminated = self.terminate_tree(0xE000_0005).is_ok();
                return Err(JobProcessWaitError::new(error, terminated));
            }
            if started.elapsed() >= timeout {
                if unsafe { TerminateJobObject(self.job, 0xE000_0006) } == 0 {
                    return Err(JobProcessWaitError::new(io::Error::last_os_error(), false));
                }
                self.wait_for_empty_job()
                    .map_err(|error| JobProcessWaitError::new(error, false))?;
                self.tree_finished = true;
                return Ok(JobProcessExit::TimedOut);
            }
        }
    }

    fn terminate_tree(&mut self, exit_code: u32) -> io::Result<()> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;
        if unsafe { TerminateJobObject(self.job, exit_code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        self.wait_for_empty_job()?;
        self.tree_finished = true;
        Ok(())
    }

    fn wait_for_empty_job(&self) -> io::Result<()> {
        use windows_sys::Win32::{
            Foundation::WAIT_OBJECT_0, System::Threading::WaitForSingleObject,
        };
        if unsafe { WaitForSingleObject(self.job, 5_000) } == WAIT_OBJECT_0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(windows)]
impl Drop for WindowsJobProcess {
    fn drop(&mut self) {
        use windows_sys::Win32::{
            Foundation::CloseHandle,
            System::{JobObjects::TerminateJobObject, Threading::WaitForSingleObject},
        };
        if !self.tree_finished {
            unsafe {
                TerminateJobObject(self.job, 0xE000_0007);
                WaitForSingleObject(self.job, 5_000);
            }
        }
        unsafe {
            CloseHandle(self.process);
            CloseHandle(self.job);
        }
    }
}

#[cfg(windows)]
fn windows_command_line(executable: &Path, arguments: &[OsString]) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    let mut command = Vec::new();
    append_quoted_windows_argument(&mut command, executable.as_os_str().encode_wide());
    for argument in arguments {
        command.push(' ' as u16);
        append_quoted_windows_argument(&mut command, argument.encode_wide());
    }
    command.push(0);
    command
}

#[cfg(windows)]
fn append_quoted_windows_argument(output: &mut Vec<u16>, argument: impl Iterator<Item = u16>) {
    let argument = argument.collect::<Vec<_>>();
    let needs_quotes = argument.is_empty()
        || argument
            .iter()
            .any(|unit| matches!(*unit, 0x20 | 0x09 | 0x22));
    if !needs_quotes {
        output.extend_from_slice(&argument);
        return;
    }
    output.push('"' as u16);
    let mut backslashes = 0_usize;
    for unit in argument {
        if unit == '\\' as u16 {
            backslashes += 1;
        } else if unit == '"' as u16 {
            output.extend(std::iter::repeat_n('\\' as u16, backslashes * 2 + 1));
            output.push(unit);
            backslashes = 0;
        } else {
            output.extend(std::iter::repeat_n('\\' as u16, backslashes));
            output.push(unit);
            backslashes = 0;
        }
    }
    output.extend(std::iter::repeat_n('\\' as u16, backslashes * 2));
    output.push('"' as u16);
}

#[cfg(windows)]
fn windows_environment_block(environment: &[(OsString, OsString)]) -> io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    let mut entries = environment.to_vec();
    entries.sort_by(|left, right| {
        left.0
            .to_string_lossy()
            .to_ascii_lowercase()
            .cmp(&right.0.to_string_lossy().to_ascii_lowercase())
    });
    let mut block = Vec::new();
    for (key, value) in entries {
        if key.is_empty()
            || key.to_string_lossy().contains('=')
            || key.encode_wide().any(|unit| unit == 0)
            || value.encode_wide().any(|unit| unit == 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid environment entry",
            ));
        }
        block.extend(key.encode_wide());
        block.push('=' as u16);
        block.extend(value.encode_wide());
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

#[cfg(not(windows))]
pub struct WindowsJobProcess;

#[cfg(not(windows))]
impl WindowsJobProcess {
    pub fn spawn(
        _executable: &Path,
        _arguments: &[OsString],
        _environment: &[(OsString, OsString)],
    ) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows Job Object is required",
        ))
    }

    pub fn wait(self, _timeout: Duration) -> Result<JobProcessExit, JobProcessWaitError> {
        Err(JobProcessWaitError::new(
            io::Error::new(io::ErrorKind::Unsupported, "Windows Job Object is required"),
            false,
        ))
    }
}
