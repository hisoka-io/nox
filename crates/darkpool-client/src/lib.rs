//! `DarkPool` client SDK: identity, key management, note operations, proof generation,
//! fee calculation, transaction building, and unified privacy client.

pub mod crypto_helpers;
pub mod identity;
pub mod key_repository;
pub mod merkle_tree;
pub mod note_factory;
pub mod note_processor;
pub mod persistence;
pub mod proof_inputs;
pub mod scan_engine;
pub mod utxo_store;

pub mod builder;
pub mod economics;
pub mod prover;

pub mod privacy_client;

pub mod config;

pub use identity::{BjjKeypair, ClientIdentity, DarkAccount, X25519Keypair};
pub use key_repository::{KeyRepository, DEFAULT_LOOKAHEAD};

pub use note_factory::{
    ChangeNoteResult, DepositNoteResult, NoteFactory, NoteFactoryError, SpendingInputs,
    TransferNoteResult,
};
pub use note_processor::{EventType, NoteProcessor, UnprocessedEvent, WalletNote};

pub use merkle_tree::{LocalMerkleTree, MerklePath, TREE_DEPTH};
pub use persistence::{load_wallet_state, save_wallet_state, PersistenceError, WalletState};
pub use scan_engine::{DarkPoolEvent, PublicMemoInfo, ScanEngine, ScanError, ScanResult};
pub use utxo_store::{IUtxoRepository, OwnedNote, UtxoStore};

pub use crypto_helpers::{
    address_to_field, aes128_decrypt, aes128_encrypt, bjj_scalar_mul, calculate_public_memo_id,
    decrypt_note_from_fields, derive_nullifier_path_a, derive_nullifier_path_b,
    derive_shared_secret_bjj, encrypt_note_for_deposit_aes, field_to_address, fr_to_u256,
    from_noir_hex, generate_dleq_proof, kdf_to_aes_key_iv, pack_ciphertext_to_fields,
    pack_note_plaintext, poseidon_hash, random_field, recipient_decrypt_3party, to_noir_decimal,
    to_noir_hex, u256_to_fr, unpack_ciphertext_from_fields, unpack_note_plaintext, CryptoError,
    DleqResult,
};
pub use proof_inputs::{
    DLEQProof, DepositInputs, GasPaymentInputs, JoinInputs, NotePlaintext, ProverInput,
    PublicClaimInputs, SplitInputs, TransferInputs, WithdrawInputs,
};

pub use economics::{FeeConfig, FeeEstimate, FeeManager, PriceData};
pub use prover::{circuits, ClientProver};

pub use builder::{
    compute_execution_hash, convert_public_inputs_to_bytes32, encode_multicall,
    format_proof_for_solidity, format_public_inputs_for_solidity, BuilderConfig, BuilderError,
    DepositProofBundle, GasPaymentBundle, JoinProofBundle, MulticallBundle, PublicClaimProofBundle,
    SplitProofBundle, TransactionBuilder, TransferProofBundle, WithdrawProofBundle,
};

pub use config::{DarkPoolConfig, GasLimits, PrivacyTxResult};
pub use privacy_client::{PrivacyClient, PrivacyClientError, Transport};
