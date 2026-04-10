//! Type-safe Rust bindings for `DarkPool` protocol contracts via `ethers::abigen`.

use ethers::prelude::*;

abigen!(
    DarkPool,
    "../../abi/DarkPool.json",
    event_derives(serde::Deserialize, serde::Serialize)
);

abigen!(
    NoxRewardPool,
    "../../abi/NoxRewardPool.json",
    event_derives(serde::Deserialize, serde::Serialize)
);

abigen!(
    MockERC20,
    "../../abi/MockERC20.json",
    event_derives(serde::Deserialize, serde::Serialize)
);

abigen!(
    NoxRegistry,
    "../../abi/NoxRegistry.json",
    event_derives(serde::Deserialize, serde::Serialize)
);

abigen!(
    RelayerMulticall,
    "../../abi/RelayerMulticall.json",
    event_derives(serde::Deserialize, serde::Serialize)
);
