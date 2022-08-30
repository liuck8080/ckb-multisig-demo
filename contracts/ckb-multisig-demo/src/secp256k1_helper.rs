use crate::error::Error;

#[link(name = "ckb-lib-secp256k1", kind = "static")]
extern "C" {
    fn ckb_secp256k1_verify(
        require_first_n: u8,
        threshold: u8,
        pubkeys_cnt: u8,
        message: *const u8,
        lock_bytes: *const u8,
        multisig_script_len: usize,
    ) -> i32;
}

pub(crate) fn validate_secp256k1_multisignautre(
    require_first_n: u8,
    threshold: u8,
    pubkeys_cnt: u8,
    message: &[u8],
    lock_bytes: &[u8],
    multisig_script_len: usize,
) -> Result<(), Error> {
    let ret = unsafe {
        ckb_secp256k1_verify(
            require_first_n,
            threshold,
            pubkeys_cnt,
            message.as_ptr(),
            lock_bytes.as_ptr(),
            multisig_script_len,
        )
    };
    if ret != 0 {
        return Err(Error::Verification);
    }
    Ok(())
}
