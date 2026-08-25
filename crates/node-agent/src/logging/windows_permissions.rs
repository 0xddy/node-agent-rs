//! Windows equivalent of the Unix `0600` log-file mode.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::path::Path;
use std::ptr;

use windows::Win32::Foundation::{CloseHandle, GENERIC_ALL, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, GRANT_ACCESS, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW,
    TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE, PROTECTED_DACL_SECURITY_INFORMATION,
    TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PWSTR;

pub(super) fn set_owner_only(path: &Path) -> io::Result<()> {
    let token = ProcessToken::open()?;
    let token_user = token.user()?;
    let user = token_user.user();

    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: GENERIC_ALL.0,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: Default::default(),
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            // With TRUSTEE_IS_SID this Win32 field contains a SID pointer,
            // despite its historical string-pointer type.
            ptstrName: PWSTR(user.User.Sid.0.cast()),
        },
    };

    let mut acl = ptr::null_mut::<ACL>();
    // SAFETY: `entry` and its SID remain alive until SetEntriesInAclW returns;
    // `acl` receives memory allocated by the LocalAlloc family.
    win32_result(unsafe { SetEntriesInAclW(Some(&[entry]), None, &mut acl) })?;
    let acl = LocalAllocation::new(acl.cast());

    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: `wide_path` is NUL-terminated and `acl` remains alive throughout
    // the call. Owner/group/SACL are intentionally left unchanged.
    win32_result(unsafe {
        SetNamedSecurityInfoW(
            PWSTR(wide_path.as_ptr().cast_mut()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(acl.as_acl()),
            None,
        )
    })
}

fn win32_result(error: windows::Win32::Foundation::WIN32_ERROR) -> io::Result<()> {
    if error.0 == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(error.0.cast_signed()))
    }
}

struct ProcessToken(HANDLE);

impl ProcessToken {
    fn open() -> io::Result<Self> {
        let mut token = HANDLE::default();
        // SAFETY: `token` is a valid output pointer and GetCurrentProcess
        // returns the documented pseudo-handle for this process.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
            .map_err(windows_error)?;
        Ok(Self(token))
    }

    fn user(&self) -> io::Result<TokenUserBuffer> {
        let mut length = 0;
        // The first call is expected to fail with ERROR_INSUFFICIENT_BUFFER and
        // populate `length`.
        let _ = unsafe { GetTokenInformation(self.0, TokenUser, None, 0, &mut length) };
        if length < size_of::<TOKEN_USER>() as u32 {
            return Err(io::Error::last_os_error());
        }

        let words = (length as usize).div_ceil(size_of::<usize>());
        let mut storage = vec![0_usize; words];
        // SAFETY: `storage` is aligned for TOKEN_USER, has at least the byte
        // length requested by Win32, and remains alive in TokenUserBuffer.
        unsafe {
            GetTokenInformation(
                self.0,
                TokenUser,
                Some(storage.as_mut_ptr().cast()),
                length,
                &mut length,
            )
        }
        .map_err(windows_error)?;
        Ok(TokenUserBuffer(storage))
    }
}

impl Drop for ProcessToken {
    fn drop(&mut self) {
        // SAFETY: the handle was returned by OpenProcessToken and is owned by
        // this guard.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct TokenUserBuffer(Vec<usize>);

impl TokenUserBuffer {
    fn user(&self) -> &TOKEN_USER {
        // SAFETY: GetTokenInformation(TokenUser) initialized this buffer as a
        // TOKEN_USER, and the usize storage provides the required alignment.
        unsafe { &*self.0.as_ptr().cast::<TOKEN_USER>() }
    }
}

struct LocalAllocation(*mut c_void);

impl LocalAllocation {
    fn new(value: *mut c_void) -> Self {
        Self(value)
    }

    fn as_acl(&self) -> *const ACL {
        self.0.cast()
    }
}

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: SetEntriesInAclW returned this LocalAlloc allocation and
            // ownership has not been transferred.
            let _ = unsafe { LocalFree(Some(HLOCAL(self.0))) };
        }
    }
}

fn windows_error(error: windows::core::Error) -> io::Error {
    io::Error::other(error)
}

use windows::Win32::Security::GetTokenInformation;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use windows::Win32::Security::Authorization::GetNamedSecurityInfoW;
    use windows::Win32::Security::{
        ACCESS_ALLOWED_ACE, EqualSid, GetAce, GetSecurityDescriptorControl, PSECURITY_DESCRIPTOR,
        PSID, SE_DACL_PROTECTED,
    };

    use crate::logging::RotatingFile;

    #[test]
    fn rotating_file_uses_a_protected_current_user_only_dacl() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("agent.log");
        let _file = RotatingFile::open(&path, 1024, 2).unwrap();
        assert_protected_current_user_only(&path);
    }

    #[test]
    fn rotating_file_tightens_an_existing_backup_dacl() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("agent.log");
        let backup = temporary.path().join("agent.log.1");
        fs::write(&backup, b"backup\n").unwrap();

        let _file = RotatingFile::open(path, 1024, 2).unwrap();
        assert_protected_current_user_only(&backup);
    }

    fn assert_protected_current_user_only(path: &Path) {
        let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut dacl = ptr::null_mut::<ACL>();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: all output pointers are valid and the path is NUL-terminated.
        win32_result(unsafe {
            GetNamedSecurityInfoW(
                PWSTR(wide_path.as_ptr().cast_mut()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                &mut descriptor,
            )
        })
        .unwrap();
        let _descriptor = LocalAllocation::new(descriptor.0);

        let mut control = 0_u16;
        let mut revision = 0_u32;
        // SAFETY: `descriptor` is the live descriptor returned above.
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }.unwrap();
        assert_ne!(control & SE_DACL_PROTECTED.0, 0, "DACL inherits: {path:?}");
        assert!(!dacl.is_null(), "missing DACL: {path:?}");
        // SAFETY: `dacl` belongs to the live security descriptor.
        assert_eq!(unsafe { (*dacl).AceCount }, 1, "unexpected DACL: {path:?}");

        let mut ace = ptr::null_mut::<c_void>();
        // SAFETY: the DACL has exactly one ACE, so index zero is valid.
        unsafe { GetAce(dacl, 0, &mut ace) }.unwrap();
        // SAFETY: SetEntriesInAclW generated an ACCESS_ALLOWED_ACE for the
        // GRANT_ACCESS entry above.
        let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        assert_eq!(ace.Header.AceType, 0, "ACE is not ACCESS_ALLOWED");

        let token = ProcessToken::open().unwrap();
        let user = token.user().unwrap();
        let ace_sid = PSID(ptr::addr_of!(ace.SidStart).cast_mut().cast());
        // SAFETY: both pointers identify live, valid SIDs.
        unsafe { EqualSid(ace_sid, user.user().User.Sid) }.unwrap();
    }
}
