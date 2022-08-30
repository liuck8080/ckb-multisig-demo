use ckb_std::error::SysError;

/// Error
#[repr(i8)]
pub enum Error {
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    // Add customized errors here...
    ArgumentsLen = -1,
    WitnessSize = -22,
    IncorrectSinceFlags = -23,
    IncorrectSinceValue = -24,
    // PubkeyBlake160Hash = -31,
    InvalidReserveField = -41,
    InvalidPubkeysCnt = -42,
    InvalidThreshold = -43,
    InvalidRequireFirstN = -44,
    MultsigScriptHash = -51,
    Verification = -52,
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        use SysError::*;
        match err {
            IndexOutOfBound => Self::IndexOutOfBound,
            ItemMissing => Self::ItemMissing,
            LengthNotEnough(_) => Self::LengthNotEnough,
            Encoding => Self::Encoding,
            Unknown(err_code) => panic!("unexpected sys error {}", err_code),
        }
    }
}

