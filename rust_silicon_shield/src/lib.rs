//! Native core of the TAUHAULITY silicon shield.
//!
//! This crate is the "FULL_RUST_PY_SHIELD" tier: a dependency free `cdylib`
//! that the Python loader binds through `ctypes`. It owns the four primitives
//! that are hot enough to justify leaving the interpreter - SHA-256, reflected
//! CRC-64, Shannon entropy and a monotonic counter - and nothing else. Page
//! locking, page protection and kernel socket tables stay in Python because
//! they are syscall bound and the interpreter overhead is irrelevant there.
//!
//! # C ABI contract
//!
//! Every exported symbol is `extern "C"`, panics never cross the boundary and
//! no export allocates memory that the caller must free:
//!
//! | symbol | signature | notes |
//! |---|---|---|
//! | `tauhaulity_version` | `() -> *const c_char` | static NUL terminated version |
//! | `tauhaulity_crc64` | `(*const u8, usize) -> u64` | reflected CRC-64, init 0 |
//! | `tauhaulity_sha256` | `(*const u8, usize, *mut u8) -> c_int` | writes 32 bytes, 0 on success |
//! | `tauhaulity_shannon` | `(*const u8, usize) -> f64` | bits per byte |
//! | `tauhaulity_qpc` | `() -> u64` | monotonic counter, unit is platform specific |
//!
//! A null data pointer is answered with a neutral value (zero checksum, zero
//! entropy, -1 status) instead of dereferencing, because a Python side bug that
//! passes `None` must not turn into a process wide access violation. The
//! Python loader additionally cross-verifies the digest and checksum against
//! `hashlib` and the pure Python table before it trusts this library at all.

pub mod crc64;
pub mod qpc;
pub mod sha256;
pub mod shannon;

use std::ffi::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

/// Semantic version of the native core, compiled into the library.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// NUL terminated version string returned by ::tauhaulity_version.
///
/// The trailing NUL is part of the ABI: Python reads the symbol with
/// `ctypes.c_char_p` and would otherwise consume adjacent read-only data.
const VERSION_C: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();

/// Return the static version string of this library.
///
/// # Safety
///
/// The returned pointer refers to immutable static storage and stays valid for
/// the lifetime of the process; the caller must not write through it or free it.
#[no_mangle]
pub extern "C" fn tauhaulity_version() -> *const c_char {
    VERSION_C.as_ptr() as *const c_char
}

/// Return the reflected CRC-64 (ECMA-182 polynomial, init 0) of a buffer.
///
/// # Safety
///
/// `data` must point to at least `len` readable bytes, or be null. A null
/// pointer returns zero, which is the checksum of an empty buffer.
#[no_mangle]
pub extern "C" fn tauhaulity_crc64(data: *const u8, len: usize) -> u64 {
    if data.is_null() {
        return 0;
    }
    let measured = catch_unwind(AssertUnwindSafe(|| {
        let bytes = unsafe { slice::from_raw_parts(data, len) };
        crc64::checksum(bytes)
    }));
    measured.unwrap_or(0)
}

/// Write the 32 byte SHA-256 digest of a buffer into `out`.
///
/// # Safety
///
/// `data` must point to at least `len` readable bytes and `out` must point
/// to at least 32 writable bytes. Returns 0 on success, -1 for a null pointer
/// and -2 when the round function panicked (only reachable through a bug).
#[no_mangle]
pub extern "C" fn tauhaulity_sha256(data: *const u8, len: usize, out: *mut u8) -> c_int {
    if data.is_null() || out.is_null() {
        return -1;
    }
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let bytes = unsafe { slice::from_raw_parts(data, len) };
        let digest = sha256::digest(bytes);
        unsafe { std::ptr::copy_nonoverlapping(digest.as_ptr(), out, digest.len()) };
    }));
    match outcome {
        Ok(()) => 0,
        Err(_) => -2,
    }
}

/// Return the Shannon entropy of a buffer in bits per byte.
///
/// # Safety
///
/// `data` must point to at least `len` readable bytes, or be null. A null
/// pointer returns zero, the entropy of an empty buffer.
#[no_mangle]
pub extern "C" fn tauhaulity_shannon(data: *const u8, len: usize) -> f64 {
    if data.is_null() {
        return 0.0;
    }
    let measured = catch_unwind(AssertUnwindSafe(|| {
        let bytes = unsafe { slice::from_raw_parts(data, len) };
        shannon::entropy(bytes)
    }));
    measured.unwrap_or(0.0)
}

/// Return a monotonically non-decreasing counter value.
///
/// The unit is QPC ticks on Windows and nanoseconds elsewhere, so only
/// differences within one process are meaningful.
#[no_mangle]
pub extern "C" fn tauhaulity_qpc() -> u64 {
    qpc::counter()
}

#[cfg(test)]
mod tests {
    use super::{
        tauhaulity_crc64, tauhaulity_qpc, tauhaulity_sha256, tauhaulity_shannon, tauhaulity_version,
        VERSION,
    };
    use std::ffi::CStr;

    #[test]
    fn version_export_is_nul_terminated_and_matches_manifest() {
        let pointer = tauhaulity_version();
        assert!(!pointer.is_null());
        let rendered = unsafe { CStr::from_ptr(pointer) }.to_str().expect("version is ASCII");
        assert_eq!(rendered, VERSION);
        assert!(!rendered.is_empty());
    }

    #[test]
    fn null_pointers_are_answered_with_neutral_values() {
        assert_eq!(tauhaulity_crc64(std::ptr::null(), 16), 0);
        assert_eq!(tauhaulity_shannon(std::ptr::null(), 16), 0.0);
        let mut out = [0u8; 32];
        assert_eq!(tauhaulity_sha256(std::ptr::null(), 0, out.as_mut_ptr()), -1);
        let payload = b"abc";
        assert_eq!(tauhaulity_sha256(payload.as_ptr(), payload.len(), std::ptr::null_mut()), -1);
    }

    #[test]
    fn ffi_digest_matches_pure_rust_digest() {
        let payload = b"tauhaulity native shield";
        let mut out = [0u8; 32];
        let status = tauhaulity_sha256(payload.as_ptr(), payload.len(), out.as_mut_ptr());
        assert_eq!(status, 0);
        assert_eq!(out, crate::sha256::digest(payload));
    }

    #[test]
    fn ffi_scalar_exports_match_module_functions() {
        let payload: Vec<u8> = (0u8..=255).collect();
        assert_eq!(
            tauhaulity_crc64(payload.as_ptr(), payload.len()),
            crate::crc64::checksum(&payload)
        );
        assert_eq!(
            tauhaulity_shannon(payload.as_ptr(), payload.len()),
            crate::shannon::entropy(&payload)
        );
    }

    #[test]
    fn empty_buffer_is_accepted() {
        // A zero length buffer with a valid but empty pointer exercises the
        // from_raw_parts(ptr, 0) path that a naive implementation gets wrong.
        let empty: [u8; 0] = [];
        assert_eq!(tauhaulity_crc64(empty.as_ptr(), 0), 0);
        assert_eq!(tauhaulity_shannon(empty.as_ptr(), 0), 0.0);
        let mut out = [0u8; 32];
        assert_eq!(tauhaulity_sha256(empty.as_ptr(), 0, out.as_mut_ptr()), 0);
        assert_eq!(
            out,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
    }

    #[test]
    fn qpc_export_is_monotonic() {
        let mut previous = tauhaulity_qpc();
        for _ in 0..1000 {
            let current = tauhaulity_qpc();
            assert!(current >= previous);
            previous = current;
        }
    }
}
