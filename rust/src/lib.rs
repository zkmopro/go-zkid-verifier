use ecdsa_spartan2::{
    paths::keys::{RS256_PROOF, RS256_VERIFYING_KEY},
    verify_circuit, PathConfig,
};
use std::ffi::{CStr, CString};
use std::cell::RefCell;
use std::path::PathBuf;

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::new("").unwrap());
}

fn set_last_error(msg: &str) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = CString::new(msg).unwrap_or_else(|_| CString::new("unknown error").unwrap());
    });
}

/// Returns a pointer to the last error message (valid until next FFI call).
#[no_mangle]
pub extern "C" fn zk_last_error() -> *const std::os::raw::c_char {
    LAST_ERROR.with(|e| e.borrow().as_ptr())
}

/// Verify the RS256 proof stored in {base_dir}/keys/.
///
/// Reads:
///   {base_dir}/keys/rs256_proof.bin
///   {base_dir}/keys/rs256_verifying.key
///
/// Returns 1 if valid, 0 if invalid, negative on error.
#[no_mangle]
pub extern "C" fn zk_rs256_verify(base_dir: *const std::os::raw::c_char) -> i32 {
    let base = match unsafe { CStr::from_ptr(base_dir) }.to_str() {
        Ok(s) => PathBuf::from(s),
        Err(e) => { set_last_error(&format!("invalid base_dir: {e}")); return -1; }
    };

    let path_config = PathConfig::new(base, false);

    let result = std::panic::catch_unwind(|| {
        verify_circuit(
            path_config.artifact_path(RS256_PROOF),
            path_config.key_path(RS256_VERIFYING_KEY),
        )
    });

    match result {
        Ok(_) => 1,
        Err(e) => {
            let msg = e.downcast_ref::<String>().map(|s| s.as_str())
                .or_else(|| e.downcast_ref::<&str>().copied())
                .unwrap_or("verify panicked");
            set_last_error(msg);
            -3
        }
    }
}
