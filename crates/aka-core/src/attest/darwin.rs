//! The Security.framework and `sysctl` binding behind [`super::PlatformAttestor`].
//!
//! Two OS facilities, one per link of the attestation:
//!
//! - `sysctl(KERN_PROC_PID)` reads the process table for a pid's parent and
//!   start time. The start time is what makes a pid a stable handle: a
//!   recycled pid gets a different one.
//! - `SecCodeCopyGuestWithAttributes` + `SecCodeCheckValidity` verify a running
//!   process's signature, and `SecCodeCopySigningInformation` reports the team,
//!   the authority, and the bundle's display name when there is a bundle.
//!
//! Every lookup here is by pid, which Apple documents as racy in isolation.
//! The mitigation is upstream and structural: the peer pid is captured when the
//! socket connection is *accepted* (see `daemon::uds`), and every resolution
//! re-checks the start time recorded at that moment, so a pid that has been
//! recycled since resolves to nothing rather than to the wrong process.
//!
//! Like [`crate::keychain::darwin`], this is the part that cannot be tested off
//! a signed Mac; the policy it serves lives in the parent module and is tested
//! everywhere.

use std::ffi::c_void;
use std::ptr;

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::base::{CFTypeRef, OSStatus};
use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::string::CFStringRef;

use super::{CodeIdentity, PlatformAttestor, ProcessInfo};

/// Opaque Security.framework handles. Only ever held behind a pointer.
#[repr(C)]
struct OpaqueSecCode(std::ffi::c_void);
type SecCodeRef = *const OpaqueSecCode;
type SecStaticCodeRef = *const OpaqueSecCode;
type SecCertificateRef = *const std::ffi::c_void;

const ERR_SEC_SUCCESS: OSStatus = 0;

/// `kSecCSDefaultFlags`: full validation, no relaxations.
const SEC_CS_DEFAULT_FLAGS: u32 = 0;
/// `kSecCSSigningInformation`, so the returned dictionary carries the
/// certificate chain the authority name is read from.
const SEC_CS_SIGNING_INFORMATION: u32 = 2;

#[link(name = "Security", kind = "framework")]
extern "C" {
    fn SecCodeCopyGuestWithAttributes(
        host: SecCodeRef,
        attributes: CFDictionaryRef,
        flags: u32,
        guest: *mut SecCodeRef,
    ) -> OSStatus;
    fn SecCodeCheckValidity(code: SecCodeRef, flags: u32, requirement: *const c_void) -> OSStatus;
    fn SecCodeCopySigningInformation(
        code: SecStaticCodeRef,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> OSStatus;
    fn SecCodeCopySelf(flags: u32, code: *mut SecCodeRef) -> OSStatus;
    fn SecCertificateCopySubjectSummary(certificate: SecCertificateRef) -> CFStringRef;

    static kSecGuestAttributePid: CFStringRef;
    static kSecCodeInfoIdentifier: CFStringRef;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    static kSecCodeInfoCertificates: CFStringRef;
    static kSecCodeInfoPList: CFStringRef;
}

extern "C" {
    fn CFRelease(cf: CFTypeRef);
    fn proc_pidpath(pid: i32, buffer: *mut c_void, buffersize: u32) -> i32;
}

/// A `SecCodeRef` that releases on drop. Security.framework hands these back
/// with a +1 retain under the Copy rule.
struct OwnedCode(SecCodeRef);

impl Drop for OwnedCode {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: obtained from a Copy-rule call, released exactly once.
            unsafe { CFRelease(self.0 as CFTypeRef) };
        }
    }
}

/// The Security.framework-backed [`PlatformAttestor`]. Stateless — every call
/// builds its own query, so there is nothing to synchronize.
#[derive(Debug, Default, Clone, Copy)]
pub struct SecurityFramework;

/// The process-wide attestor. The signing team of the running broker is read
/// once: it cannot change without the process being replaced.
pub fn security_framework() -> &'static SecurityFramework {
    &SecurityFramework
}

/// `struct kinfo_proc` is large and its layout is stable ABI, but binding it
/// field-by-field is fragile. Only two values are needed, and both sit at
/// documented offsets inside the two substructures, so the buffer is read as
/// bytes and the fields are pulled out by offset.
///
/// Offsets are absolute within `kinfo_proc`, taken from `offsetof` against the
/// macOS SDK headers rather than derived by hand — `extern_proc` opens with a
/// union whose `p_starttime` arm overlaps the list pointers, which is why the
/// start time sits at offset 0 rather than after them.
///
/// `assert_kinfo_layout_matches_the_running_kernel` re-derives the two fields
/// from a live process, so a future SDK that moves them fails a test instead of
/// silently reading adjacent bytes.
mod kinfo {
    /// `kp_proc.p_starttime`, a `timeval` of two 64-bit words.
    pub const P_STARTTIME: usize = 0;
    /// `kp_eproc.e_ppid`.
    pub const E_PPID: usize = 560;
    /// `sizeof(struct kinfo_proc)` on 64-bit macOS.
    pub const SIZE: usize = 648;
}

fn sysctl_proc(pid: i32) -> Option<(i32, u64)> {
    let mut mib: [libc::c_int; 4] = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
    let mut buf = vec![0u8; kinfo::SIZE];
    let mut len = buf.len();
    // SAFETY: mib is a 4-element control vector matching KERN_PROC_PID, and
    // buf is at least `kinfo_proc`-sized. sysctl writes at most `len` bytes and
    // updates `len` with what it wrote.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            &mut len,
            ptr::null_mut(),
            0,
        )
    };
    // A dead process returns success with a zero-length result rather than an
    // error, so the length is the liveness check.
    if rc != 0 || len < kinfo::SIZE {
        return None;
    }
    let ppid = i32::from_ne_bytes(buf[kinfo::E_PPID..kinfo::E_PPID + 4].try_into().ok()?);
    // `p_starttime` is a `timeval`: two 64-bit words on this ABI.
    let secs = i64::from_ne_bytes(buf[kinfo::P_STARTTIME..kinfo::P_STARTTIME + 8].try_into().ok()?);
    let usecs = i64::from_ne_bytes(
        buf[kinfo::P_STARTTIME + 8..kinfo::P_STARTTIME + 16]
            .try_into()
            .ok()?,
    );
    let start = (secs as u64).checked_mul(1_000_000)?.checked_add(usecs as u64)?;
    Some((ppid, start))
}

fn pid_path(pid: i32) -> Option<String> {
    // PROC_PIDPATHINFO_MAXSIZE is 4 * MAXPATHLEN.
    let mut buf = vec![0u8; 4 * 1024];
    // SAFETY: buf is writable for the length passed.
    let len = unsafe { proc_pidpath(pid, buf.as_mut_ptr() as *mut std::ffi::c_void, buf.len() as u32) };
    if len <= 0 {
        return None;
    }
    buf.truncate(len as usize);
    String::from_utf8(buf).ok()
}

/// Verified signing information for a live process, by pid.
fn signing_info(pid: i32) -> Option<CodeIdentity> {
    let pid_value = CFNumber::from(pid);
    // SAFETY: kSecGuestAttributePid is an immortal CFString constant; the
    // get-rule wrapper retains rather than consumes it.
    let attr_key = unsafe { CFString::wrap_under_get_rule(kSecGuestAttributePid) };
    let attrs = CFDictionary::from_CFType_pairs(&[(attr_key, pid_value.as_CFType())]);

    let mut code: SecCodeRef = ptr::null();
    // SAFETY: attrs outlives the call; `code` receives a +1 reference which
    // OwnedCode releases.
    let status = unsafe {
        SecCodeCopyGuestWithAttributes(
            ptr::null(),
            attrs.as_concrete_TypeRef(),
            SEC_CS_DEFAULT_FLAGS,
            &mut code,
        )
    };
    if status != ERR_SEC_SUCCESS || code.is_null() {
        return None;
    }
    let code = OwnedCode(code);

    // The signature must actually verify. Without this the call above would
    // happily describe a tampered binary.
    // SAFETY: `code.0` is a live SecCodeRef.
    if unsafe { SecCodeCheckValidity(code.0, SEC_CS_DEFAULT_FLAGS, ptr::null()) } != ERR_SEC_SUCCESS
    {
        return None;
    }

    let mut info: CFDictionaryRef = ptr::null();
    // SAFETY: `code.0` is live; `info` receives a +1 dictionary.
    let status =
        unsafe { SecCodeCopySigningInformation(code.0, SEC_CS_SIGNING_INFORMATION, &mut info) };
    if status != ERR_SEC_SUCCESS || info.is_null() {
        return None;
    }
    // SAFETY: +1 from the Copy-rule call above; the wrapper takes ownership.
    let info: CFDictionary<CFString, CFType> = unsafe { CFDictionary::wrap_under_create_rule(info) };

    let identifier = dict_string(&info, unsafe { kSecCodeInfoIdentifier })?;
    let team_id = dict_string(&info, unsafe { kSecCodeInfoTeamIdentifier });
    let signer = leaf_common_name(&info).and_then(|cn| super::signer_org(&cn));
    let program = bundle_display_name(&info);

    Some(CodeIdentity {
        identifier,
        team_id,
        signer,
        program,
    })
}

/// Re-read a nested CF dictionary with string keys. `CFType::downcast` only
/// knows the untyped container, so the marker types are restored here rather
/// than at every use.
fn typed_dict(value: CFType) -> Option<CFDictionary<CFString, CFType>> {
    let untyped = value.downcast::<CFDictionary<*const c_void, *const c_void>>()?;
    // SAFETY: the same dictionary, re-wrapped with the key/value marker types
    // its contents actually have; the get-rule wrapper retains rather than
    // consumes, so both wrappers release exactly once.
    Some(unsafe {
        CFDictionary::wrap_under_get_rule(untyped.as_concrete_TypeRef() as CFDictionaryRef)
    })
}

fn dict_string(info: &CFDictionary<CFString, CFType>, key: CFStringRef) -> Option<String> {
    // SAFETY: the kSecCodeInfo* constants are immortal CFStrings.
    let key = unsafe { CFString::wrap_under_get_rule(key) };
    let value = info.find(&key)?;
    value.downcast::<CFString>().map(|s| s.to_string())
}

/// The signing certificate chain's leaf common name, e.g.
/// `Developer ID Application: Anthropic, PBC (Q6L2SF6YDW)`.
fn leaf_common_name(info: &CFDictionary<CFString, CFType>) -> Option<String> {
    // SAFETY: immortal constant.
    let key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoCertificates) };
    // `downcast` only knows the untyped container types, so the array is read
    // as raw elements and the leaf is reinterpreted below.
    let certs = info.find(&key)?.downcast::<CFArray<*const c_void>>()?;
    let leaf = *certs.get(0)?;
    // SAFETY: element 0 of kSecCodeInfoCertificates is the leaf
    // SecCertificateRef; the returned CFString is +1 under the Copy rule.
    let summary = unsafe { SecCertificateCopySubjectSummary(leaf as SecCertificateRef) };
    if summary.is_null() {
        return None;
    }
    // SAFETY: +1 from the Copy-rule call; the wrapper takes ownership.
    Some(unsafe { CFString::wrap_under_create_rule(summary) }.to_string())
}

/// The bundle's display name, when the image is a bundle at all. A bare signed
/// executable reports no plist — `codesign` renders that as
/// `Info.plist=not bound` — and gets `None`, which is what separates
/// `Verified` from `VerifiedSigner` upstream.
fn bundle_display_name(info: &CFDictionary<CFString, CFType>) -> Option<String> {
    // SAFETY: immortal constant.
    let key = unsafe { CFString::wrap_under_get_rule(kSecCodeInfoPList) };
    let plist = typed_dict(info.find(&key)?.clone())?;
    for name in ["CFBundleDisplayName", "CFBundleName"] {
        if let Some(value) = plist.find(CFString::new(name)) {
            if let Some(text) = value.downcast::<CFString>() {
                let text = text.to_string();
                if !text.trim().is_empty() {
                    return Some(text);
                }
            }
        }
    }
    None
}

/// The running broker's own signing team.
fn own_team() -> Option<String> {
    let mut code: SecCodeRef = ptr::null();
    // SAFETY: `code` receives a +1 reference which OwnedCode releases.
    if unsafe { SecCodeCopySelf(SEC_CS_DEFAULT_FLAGS, &mut code) } != ERR_SEC_SUCCESS
        || code.is_null()
    {
        return None;
    }
    let code = OwnedCode(code);
    let mut info: CFDictionaryRef = ptr::null();
    // SAFETY: `code.0` is live; `info` receives a +1 dictionary.
    if unsafe { SecCodeCopySigningInformation(code.0, SEC_CS_SIGNING_INFORMATION, &mut info) }
        != ERR_SEC_SUCCESS
        || info.is_null()
    {
        return None;
    }
    // SAFETY: +1 from the Copy-rule call above.
    let info: CFDictionary<CFString, CFType> = unsafe { CFDictionary::wrap_under_create_rule(info) };
    dict_string(&info, unsafe { kSecCodeInfoTeamIdentifier })
}

impl PlatformAttestor for SecurityFramework {
    fn process(&self, pid: i32) -> Option<ProcessInfo> {
        let (ppid, start_time) = sysctl_proc(pid)?;
        Some(ProcessInfo {
            pid,
            ppid,
            start_time,
            // A process with no readable path still has an ancestry worth
            // walking, so this is not fatal — it just cannot be classified as
            // a shell or an interpreter.
            path: pid_path(pid).unwrap_or_default(),
        })
    }

    fn code_identity(&self, pid: i32, expect_start: u64) -> Option<CodeIdentity> {
        // Re-check the start time on both sides of the signature read. The
        // first check rejects a pid recycled before the call; the second
        // rejects one recycled during it, which is the whole pid-reuse race
        // Apple warns about for pid-keyed guest lookups.
        if sysctl_proc(pid)?.1 != expect_start {
            return None;
        }
        let identity = signing_info(pid)?;
        if sysctl_proc(pid)?.1 != expect_start {
            return None;
        }
        Some(identity)
    }

    fn own_team_id(&self) -> Option<String> {
        static OWN: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
        OWN.get_or_init(own_team).clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `kinfo_proc` fields are read by byte offset, so this pins both
    /// against values the OS reports another way. Without the `getppid`
    /// comparison a wrong offset still yields a plausible-looking number.
    #[test]
    fn assert_kinfo_layout_matches_the_running_kernel() {
        let me = std::process::id() as i32;
        let info = SecurityFramework.process(me).expect("own process readable");
        assert_eq!(info.pid, me);

        // SAFETY: getppid is always safe and cannot fail.
        let real_ppid = unsafe { libc::getppid() };
        assert_eq!(info.ppid, real_ppid, "e_ppid offset is wrong");

        // A start time is a wall-clock microsecond count, so it must land in a
        // sane range rather than merely be non-zero — the check that a wrong
        // offset reading adjacent bytes would fail.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let started_secs = info.start_time / 1_000_000;
        assert!(
            started_secs <= now_secs && started_secs > now_secs - 86_400 * 365,
            "p_starttime offset is wrong: {started_secs} is not a plausible start time \
             against now={now_secs}"
        );
    }

    #[test]
    fn a_processes_path_is_readable() {
        let me = std::process::id() as i32;
        let info = SecurityFramework.process(me).expect("own process readable");
        assert!(
            info.path.contains("aka_core") || info.path.contains("deps"),
            "expected the test binary's own path, got {:?}",
            info.path
        );
    }

    #[test]
    fn a_pid_that_cannot_exist_reads_as_gone() {
        assert!(SecurityFramework.process(-1).is_none());
    }

    #[test]
    fn a_mismatched_start_time_refuses_to_resolve() {
        let me = std::process::id() as i32;
        assert!(SecurityFramework.code_identity(me, 1).is_none());
    }
}

#[cfg(test)]
mod live_probe {
    use super::*;

    /// Not a unit test: a probe for verifying the Security.framework binding
    /// against real signed processes on a developer machine.
    /// `cargo test -p aka-core --lib live_probe -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn describe_running_processes() {
        println!("own team: {:?}", SecurityFramework.own_team_id());
        for pid in [1i32, std::process::id() as i32] {
            let info = SecurityFramework.process(pid);
            let code = info
                .as_ref()
                .and_then(|i| SecurityFramework.code_identity(pid, i.start_time));
            println!("pid {pid}: path={:?}", info.as_ref().map(|i| &i.path));
            println!("   code={code:?}");
        }
    }
}
