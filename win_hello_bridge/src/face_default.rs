//! Makes the Windows Hello dialog open on face instead of PIN.
//!
//! The dialog starts with the method of the last Windows sign-in, stored in
//! HKLM\...\Authentication\LogonUI\LastLoggedOnProvider. Only SYSTEM and
//! Administrators may write that value, so a scheduled task running as SYSTEM
//! sets it to the face provider; the user is allowed to start that task.
//!
//! Best effort: if the task is missing or slow, the dialog opens as before.

use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ};

const FACE_PROVIDER: &str = "{8AF662BF-65A0-4D0A-A540-A338A999D36F}";
const TASK_NAME: &str = r"\WSL-Hello-sudo\FaceDefault";
const MAX_WAIT: Duration = Duration::from_millis(1500);
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub(crate) fn ensure_face_default() {
    if last_provider_is_face() {
        return;
    }
    let started = Command::new(r"C:\Windows\System32\schtasks.exe")
        .args(["/run", "/tn", TASK_NAME])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !started {
        return;
    }
    // schtasks /run returns before the task is done; wait for the value.
    let deadline = Instant::now() + MAX_WAIT;
    while Instant::now() < deadline {
        if last_provider_is_face() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn last_provider_is_face() -> bool {
    read_last_provider().map_or(false, |v| v.eq_ignore_ascii_case(FACE_PROVIDER))
}

fn read_last_provider() -> Option<String> {
    let subkey = wide(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI");
    let value = wide("LastLoggedOnProvider");
    let mut buf = [0u16; 64];
    let mut size = (buf.len() * 2) as u32;
    let err = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey.as_ptr()),
            PCWSTR(value.as_ptr()),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if err != ERROR_SUCCESS {
        return None;
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..len]))
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
