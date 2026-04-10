//! Type-safe bindings and deployment utilities for `DarkPool` protocol contracts.

pub mod bindings;
pub mod deployer;

pub use bindings::{DarkPool, MockERC20, NoxRegistry, NoxRewardPool, RelayerMulticall};
pub use deployer::{
    CompliancePk, ContractDeployer, DeployError, DeployedContracts, VerifierAddresses,
};
