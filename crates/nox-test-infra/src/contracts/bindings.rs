//! Type-safe Rust bindings for Nox test contracts via `ethers::abigen`.

use ethers::prelude::*;

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
