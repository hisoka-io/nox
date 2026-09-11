// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

interface IRewardPoolFixture {
    function depositRewards(address asset, uint256 amount) external;
}

interface IERC20Fixture {
    function approve(address spender, uint256 amount) external returns (bool);
}

contract RevertingPaymentChild {
    function depositThenRevert(address pool, address asset, uint256 amount) external {
        IERC20Fixture(asset).approve(pool, amount);
        IRewardPoolFixture(pool).depositRewards(asset, amount);
        revert("rolled back");
    }

    function depositSuccessfully(address pool, address asset, uint256 amount) external {
        IERC20Fixture(asset).approve(pool, amount);
        IRewardPoolFixture(pool).depositRewards(asset, amount);
    }
}

contract CatchingPaymentParent {
    function catchPayment(address child, bytes calldata callData) external returns (bool) {
        (bool ok, ) = child.call(callData);
        require(!ok, "child must revert");
        return true;
    }

    function forwardPayment(address child, bytes calldata callData) external returns (bool) {
        (bool ok, ) = child.call(callData);
        require(ok, "child must succeed");
        return true;
    }
}
