//! Windows' equivalent of the 0600 and 0700 modes used for secrets on Unix: access lists.
//!
//! A new secret gets a private list (this user and SYSTEM, nothing inherited), set before any
//! secret byte is written. On load, a file is refused if anyone but this user, SYSTEM or
//! Administrators may access it, the same accounts OpenSSH accepts on a private key on Windows.
//! A volume without access lists (FAT, exFAT) is refused rather than trusted.

use std::ffi::{c_void, OsStr};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SetNamedSecurityInfoW,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const SYSTEM: &str = "S-1-5-18";
const ADMINISTRATORS: &str = "S-1-5-32-544";
const ACE_ALLOW: u8 = 0; // ACCESS_ALLOWED_ACE_TYPE
const ACE_DENY: u8 = 1; // ACCESS_DENIED_ACE_TYPE

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

/// Frees what Windows allocated with LocalAlloc.
struct Local(*mut c_void);

impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an API documented to allocate it with LocalAlloc, once.
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }
}

fn sid_text(sid: PSID) -> io::Result<String> {
    let mut text: *mut u16 = null_mut();
    // SAFETY: sid is a valid SID owned by the caller; text receives a LocalAlloc'd, NUL-terminated string.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _free = Local(text as *mut c_void);
    // SAFETY: text is NUL-terminated, per the call above.
    let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
    // SAFETY: the first len units were just read.
    Ok(String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) }))
}

fn current_user_sid() -> io::Result<String> {
    let mut token: HANDLE = null_mut();
    // SAFETY: the current-process pseudo handle needs no closing; token receives a handle closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut size = 0u32;
    // SAFETY: a size query, with no buffer; it fails by design and sets size.
    unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut size) };
    // u64s, so the buffer is aligned for TOKEN_USER.
    let mut buffer = vec![0u64; (size as usize).div_ceil(8).max(1)];
    // SAFETY: buffer holds at least size bytes.
    let got = unsafe { GetTokenInformation(token, TokenUser, buffer.as_mut_ptr() as *mut c_void, size, &mut size) };
    let result = if got == 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: on success the buffer starts with a TOKEN_USER whose SID points inside it.
        sid_text(unsafe { (*(buffer.as_ptr() as *const TOKEN_USER)).User.Sid })
    };
    // SAFETY: token was opened above and is closed once.
    unsafe { CloseHandle(token) };
    result
}

/// Replace a path's access list with the one in `sddl`, dropping everything inherited.
fn set_access_list(path: &Path, sddl: &str) -> io::Result<()> {
    let sddl = wide(OsStr::new(sddl));
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: sddl is NUL-terminated; descriptor receives a LocalAlloc'd security descriptor.
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut descriptor, null_mut()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _free = Local(descriptor);
    let (mut present, mut defaulted, mut dacl) = (0, 0, null_mut::<ACL>());
    // SAFETY: descriptor is valid; dacl points inside it and is used while _free holds it.
    if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let path = wide(path.as_os_str());
    // SAFETY: path is NUL-terminated and dacl is valid; only the access list is set.
    let status = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

pub fn make_file_private(path: &Path) -> io::Result<()> {
    set_access_list(path, &format!("D:P(A;;FA;;;{})(A;;FA;;;SY)", current_user_sid()?))
}

/// As for a file, and inherited by what is later created inside.
pub fn make_dir_private(path: &Path) -> io::Result<()> {
    set_access_list(path, &format!("D:P(A;OICI;FA;;;{})(A;OICI;FA;;;SY)", current_user_sid()?))
}

/// The same answer `mode & 0o077` gives on Unix: why this file is not private, if it is not.
pub fn private_file_problem(path: &Path) -> io::Result<Option<String>> {
    let me = current_user_sid()?;
    let fix = format!("; expected only your account. To fix it: icacls \"{}\" /inheritance:r /grant:r \"%USERNAME%:F\"", path.display());
    let shown = wide(path.as_os_str());
    let (mut owner, mut dacl, mut descriptor): (PSID, *mut ACL, PSECURITY_DESCRIPTOR) = (null_mut(), null_mut(), null_mut());
    // SAFETY: shown is NUL-terminated; owner and dacl point inside descriptor, held by _free below.
    let status = unsafe {
        GetNamedSecurityInfoW(
            shown.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _free = Local(descriptor);
    if dacl.is_null() {
        return Ok(Some(format!("has no access list, so every account can read it{fix}")));
    }
    let trusted = |sid: &str| sid == me || sid == SYSTEM || sid == ADMINISTRATORS;
    let owner = sid_text(owner)?;
    if !trusted(&owner) {
        return Ok(Some(format!("is owned by another account ({owner}){fix}")));
    }
    let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: dacl is valid; info is the size this information class fills.
    if unsafe { GetAclInformation(dacl, &mut info as *mut _ as *mut c_void, std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32, AclSizeInformation) } == 0 {
        return Err(io::Error::last_os_error());
    }
    for index in 0..info.AceCount {
        let mut ace: *mut c_void = null_mut();
        // SAFETY: index is below AceCount; ace points inside dacl.
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: every ACE begins with an ACE_HEADER.
        let kind = unsafe { (*(ace as *const ACE_HEADER)).AceType };
        match kind {
            ACE_DENY => {}
            ACE_ALLOW => {
                // SAFETY: an allow ACE is an ACCESS_ALLOWED_ACE, whose SID starts at SidStart.
                let sid = sid_text(unsafe { std::ptr::addr_of!((*(ace as *const ACCESS_ALLOWED_ACE)).SidStart) } as PSID)?;
                if !trusted(&sid) {
                    return Ok(Some(format!("can be accessed by another account ({sid}){fix}")));
                }
            }
            // Conditional and object entries can grant access in ways not read here.
            other => return Ok(Some(format!("has an access entry of a kind this daemon does not read ({other}){fix}"))),
        }
    }
    Ok(None)
}
