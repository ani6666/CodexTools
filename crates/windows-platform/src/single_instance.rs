use std::{ffi::OsStr, io, os::windows::ffi::OsStrExt, ptr};

use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, WAIT_OBJECT_0},
    System::{
        DataExchange::COPYDATASTRUCT,
        Threading::{
            CreateEventW, CreateMutexW, ReleaseMutex, ResetEvent, SetEvent, WaitForSingleObject,
        },
    },
    UI::WindowsAndMessaging::{
        FindWindowW, SMTO_ABORTIFHUNG, SMTO_BLOCK, SendMessageTimeoutW, WM_COPYDATA,
    },
};

const STARTUP_WAIT_MILLIS: u32 = 5_000;
const ACTIVATE_WAIT_MILLIS: u32 = 2_000;
const WMCOPYDATA_SINGLE_INSTANCE_DATA: usize = 1_542;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstanceActivationStatus {
    Delivered,
    TargetUnavailable,
    PrimaryUnresponsive,
}

#[derive(Debug)]
pub enum InstanceStartupDisposition {
    Primary(WindowsInstanceStartupGate),
    Secondary(InstanceActivationStatus),
}

/// 在 Tauri 插件 setup 之前取得的 Windows 启动门禁。
///
/// 官方 single-instance 插件继续负责窗口激活；这里的 mutex + ready event 只关闭
/// “主进程已持有 mutex、但插件消息窗尚未创建”期间第二进程继续启动的竞态。
#[derive(Debug)]
pub struct WindowsInstanceStartupGate {
    mutex: isize,
    ready_event: isize,
}

impl WindowsInstanceStartupGate {
    pub fn acquire(identifier: &str) -> io::Result<InstanceStartupDisposition> {
        validate_identifier(identifier)?;
        let mutex_name = wide(&format!("{identifier}-startup-gate"));
        let ready_name = wide(&format!("{identifier}-startup-ready"));
        let class_name = wide(&format!("{identifier}-sic"));
        let window_name = wide(&format!("{identifier}-siw"));

        let mutex = unsafe { CreateMutexW(ptr::null(), 1, mutex_name.as_ptr()) };
        if mutex.is_null() {
            return Err(io::Error::last_os_error());
        }
        let already_exists = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        let ready_event = unsafe { CreateEventW(ptr::null(), 1, 0, ready_name.as_ptr()) };
        if ready_event.is_null() {
            if !already_exists {
                unsafe { ReleaseMutex(mutex) };
            }
            unsafe { CloseHandle(mutex) };
            return Err(io::Error::last_os_error());
        }

        if already_exists {
            let status = if unsafe { WaitForSingleObject(ready_event, STARTUP_WAIT_MILLIS) }
                == WAIT_OBJECT_0
            {
                activate_primary(&class_name, &window_name)
            } else {
                InstanceActivationStatus::TargetUnavailable
            };
            unsafe {
                CloseHandle(ready_event);
                CloseHandle(mutex);
            }
            return Ok(InstanceStartupDisposition::Secondary(status));
        }

        if unsafe { ResetEvent(ready_event) } == 0 {
            unsafe {
                CloseHandle(ready_event);
                ReleaseMutex(mutex);
                CloseHandle(mutex);
            }
            return Err(io::Error::last_os_error());
        }
        Ok(InstanceStartupDisposition::Primary(Self {
            mutex: mutex as isize,
            ready_event: ready_event as isize,
        }))
    }

    /// 仅在官方插件、生产 backend 与主窗口 setup 全部成功后发布。
    pub fn mark_ready(&self) -> io::Result<()> {
        if unsafe { SetEvent(self.ready_event as _) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Drop for WindowsInstanceStartupGate {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.ready_event as _);
            ReleaseMutex(self.mutex as _);
            CloseHandle(self.mutex as _);
        }
    }
}

fn activate_primary(class_name: &[u16], window_name: &[u16]) -> InstanceActivationStatus {
    let target = unsafe { FindWindowW(class_name.as_ptr(), window_name.as_ptr()) };
    if target.is_null() {
        return InstanceActivationStatus::TargetUnavailable;
    }

    // 固定空 payload：不读取、不记录、不转发第二实例 argv/cwd/env。
    let payload = [0_u8];
    let data = COPYDATASTRUCT {
        dwData: WMCOPYDATA_SINGLE_INSTANCE_DATA,
        cbData: payload.len() as u32,
        lpData: payload.as_ptr().cast_mut().cast(),
    };
    let mut result = 0_usize;
    let sent = unsafe {
        SendMessageTimeoutW(
            target,
            WM_COPYDATA,
            0,
            (&raw const data) as isize,
            SMTO_ABORTIFHUNG | SMTO_BLOCK,
            ACTIVATE_WAIT_MILLIS,
            &raw mut result,
        )
    };
    if sent == 0 {
        InstanceActivationStatus::PrimaryUnresponsive
    } else {
        InstanceActivationStatus::Delivered
    }
}

fn validate_identifier(identifier: &str) -> io::Result<()> {
    if identifier.is_empty()
        || identifier.len() > 128
        || !identifier
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'.' | b'-' | b'_'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid desktop instance identifier",
        ));
    }
    Ok(())
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
