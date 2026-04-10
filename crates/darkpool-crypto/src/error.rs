use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CryptoError {
    #[error("Invalid key format")]
    InvalidKey,
    #[error("Point not on curve")]
    InvalidPoint,
    #[error("Point not in prime-order subgroup")]
    SubgroupCheckFailed,
    #[error("Invalid field operation")]
    InvalidOperation,
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Field conversion error")]
    FieldConversion,
    #[error("Input exceeds maximum length of {max} bytes (got {got})")]
    InputTooLong { max: usize, got: usize },
}
