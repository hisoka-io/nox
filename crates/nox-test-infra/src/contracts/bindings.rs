//! Type-safe Rust bindings for Nox test contracts, generated with `alloy::sol!`
//! from the Hardhat artifacts in `abi/` (ABI and creation bytecode).

alloy::sol!(
    #[sol(rpc)]
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    NoxRewardPool,
    "../../abi/NoxRewardPool.json"
);

alloy::sol!(
    #[sol(rpc)]
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    MockERC20,
    "../../abi/MockERC20.json"
);

alloy::sol!(
    #[sol(rpc)]
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    NoxRegistry,
    "../../abi/NoxRegistry.json"
);
