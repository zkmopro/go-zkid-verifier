use ecdsa_spartan2::{
    verify_circuit, CertChainRsa2048, CertChainRsa4096, DeviceSigRsa2048, PathConfig, RsaKeySize,
};
use ff::PrimeField;
use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::path::PathBuf;
use subtle::ConstantTimeEq;

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::new("").unwrap());
}

fn set_last_error(msg: &str) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() =
            CString::new(msg).unwrap_or_else(|_| CString::new("unknown error").unwrap());
    });
}

/// Returns a pointer to the last error message (valid until next FFI call).
#[no_mangle]
pub extern "C" fn zk_last_error() -> *const std::os::raw::c_char {
    LAST_ERROR.with(|e| e.borrow().as_ptr())
}

/// Link-verify: verify cert-chain + device-sig proofs and check pk_commit equality.
///
/// Reads from {base_dir}/keys/:
///   - cert_chain proof (rs2048 or rs4096 depending on cert_chain_type)
///   - device_sig_rs2048 proof
///   - corresponding verifying keys
///
/// cert_chain_type: 0 = rs2048, 1 = rs4096
/// Returns 1 if both proofs valid and pk_commit matches, 0 if mismatch, negative on error.
#[no_mangle]
pub extern "C" fn zk_link_verify(
    base_dir: *const std::os::raw::c_char,
    cert_chain_type: std::os::raw::c_int,
) -> i32 {
    let base = match unsafe { CStr::from_ptr(base_dir) }.to_str() {
        Ok(s) => PathBuf::from(s),
        Err(e) => {
            set_last_error(&format!("invalid base_dir: {e}"));
            return -1;
        }
    };

    let path_config = PathConfig::new(base, false);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Select cert-chain proof/VK file names based on cert_chain_type
        let (cc_proof_file, cc_vk_file): (&str, &str) = if cert_chain_type == 1 {
            (CertChainRsa4096::PROOF, CertChainRsa4096::VERIFYING_KEY)
        } else {
            (CertChainRsa2048::PROOF, CertChainRsa2048::VERIFYING_KEY)
        };

        // Verify cert-chain proof
        let cc_public_values = verify_circuit(
            path_config.artifact_path(cc_proof_file),
            path_config.key_path(cc_vk_file),
        );

        // Verify device-sig proof
        let ds_public_values = verify_circuit(
            path_config.artifact_path(DeviceSigRsa2048::PROOF),
            path_config.key_path(DeviceSigRsa2048::VERIFYING_KEY),
        );

        // pk_commit is at index 1 for cert-chain (after subject_dn_hash)
        // pk_commit is at index 0 for device-sig (first output)
        let pk_commit_a = &cc_public_values[1];
        let pk_commit_b = &ds_public_values[0];

        let commits_match: bool = pk_commit_a
            .to_repr()
            .as_ref()
            .ct_eq(pk_commit_b.to_repr().as_ref())
            .into();

        if commits_match {
            1
        } else {
            0
        }
    }));

    match result {
        Ok(v) => v,
        Err(e) => {
            let msg = e
                .downcast_ref::<String>()
                .map(|s| s.as_str())
                .or_else(|| e.downcast_ref::<&str>().copied())
                .unwrap_or("link-verify panicked");
            set_last_error(msg);
            -3
        }
    }
}
