# Smilee Finance
## Contest Summary

Code under review: [2024-02-smilee-finance](https://github.com/sherlock-audit/2024-02-smilee-finance) (3306 nSLOC)

Contest Page: [smilee-contest](https://audits.sherlock.xyz/contests/180)

Placement: #2/173

## Findings Summary
| Severity | Title |
|------------|---------|
| [Medium-1](#m-1-whenever-swapprice-oracleprice-minting-via-positionmanager-will-revert-due-to-not-enough-funds-being-obtained-from-user)  | Whenever swapPrice oraclePrice, minting via PositionManager will revert, due to not enough funds being obtained from user. |
| [Medium-2](#m-2-the-refunding-feature-in-the-positionmanager-contract-will-always-revert-due-to-insufficient-approval)  |The refunding feature in the PositionManager contract will always revert due to insufficient approval|
| [Medium-3](#m-3-complete-dos-of-every-dvps-minting-and-burning-due-to-insufficient-access-controls-within-feemanagertrackvaultfee)  |Complete DoS of every DVP's minting and burning, due to insufficient access controls within FeeManager::trackVaultFee.|

# Findings

## [M-1] Whenever swapPrice oraclePrice, minting via PositionManager will revert, due to not enough funds being obtained from user.

Submitted by: **juan**, cawfree, panprog (Lead Watson)

### Summary
In [`PositionManager::mint()`](https://github.com/sherlock-audit/2024-02-smilee-finance/blob/3241f1bf0c8e951a41dd2e51997f64ef3ec017bd/smilee-v2-contracts/src/periphery/PositionManager.sol#L91-L178), `obtainedPremium` is calculated in a different way to the actual premium needed, and this will lead to a revert, denying service to users.

### Vulnerability Detail
In [`PositionManager::mint()`](https://github.com/sherlock-audit/2024-02-smilee-finance/blob/3241f1bf0c8e951a41dd2e51997f64ef3ec017bd/smilee-v2-contracts/src/periphery/PositionManager.sol#L91-L178), the PM gets `obtainedPremium` from `DVP::premium()`:

```solidity
(obtainedPremium, ) = dvp.premium(params.strike, params.notionalUp, params.notionalDown);
```

Then the actual premium used when minting by the DVP is obtained via the following [code](https://github.com/sherlock-audit/2024-02-smilee-finance/blob/3241f1bf0c8e951a41dd2e51997f64ef3ec017bd/smilee-v2-contracts/src/DVP.sol#L152-L155):

Determining option premium
From the code above, we can see that the actual premium uses the greater of the two price options. However, [`DVP::premium()`](https://github.com/sherlock-audit/2024-02-smilee-finance/blob/3241f1bf0c8e951a41dd2e51997f64ef3ec017bd/smilee-v2-contracts/src/IG.sol#L94-L113) only uses the oracle price to determine the `obtainedPremium`.

This leads to the opportunity for `premiumSwap premiumOrac`, so in the PositionManager, `obtainedPremium` is less than the actual premium required to mint the position in the DVP contract.

Thus, when the DVP contract tries to collect the premium from the PositionManager, it will revert due to insufficient balance in the PositionManager:

```solidity
IERC20Metadata(baseToken).safeTransferFrom(msg.sender, vault, premium_ + vaultFee);
```

### Impact
Whenever `swapPrice oraclePrice`, minting positions via the PositionManager will revert. This is a denial of service to users and this disruption of core protocol functionality can last extended periods of time.

### Code Snippet
https://github.com/sherlock-audit/2024-02-smilee-finance/blob/3241f1bf0c8e951a41dd2e51997f64ef3ec017bd/smilee-v2-contracts/src/DVP.sol#L152-L155

### Tool used
Manual Review

### Recommendation
When calculating `obtainedPremium`, consider also using the premium from `swapPrice` if it is greater than the premium calculated from `oraclePrice`.


## [M-2] The refunding feature in the PositionManager contract will always revert due to insufficient approval

Submitted by: **juan**, panprog (Lead Watson)

### Vulnerability Detail
The following logic is used to refund users when extra tokens were sent to the PositionManager contract:

```solidity
if (obtainedPremium premium) {
    baseToken.safeTransferFrom(address(this), msg.sender, obtainedPremium - premium);
} 
```

This logic was added as a fix to a bug found in the previous audit, but this logic has a severe issue. It uses `safeTransferFrom` to send the funds from itself. This requires the contract to first approve itself to increase it's allowance. However there is no logic in the contract to provide approval to itself. Therefore, this refunding feature will revert EVERY TIME.

### Impact
Whenever funds are supposed to be refunded from the PositionManager, it will revert and the user will not be able to mint their DVP position, severely disrupting protocol functionality.

### Code Snippet
https://github.com/sherlock-audit/2024-02-smilee-finance/blob/3241f1bf0c8e951a41dd2e51997f64ef3ec017bd/smilee-v2-contracts/src/periphery/PositionManager.sol#L139-L141

### Tool used
Foundry testing, no manual review

### Recommendation
Use `safeTransfer()` instead of `safeTransferFrom()` to refund.

```diff
if (obtainedPremium premium) {
-    baseToken.safeTransferFrom(address(this), msg.sender, obtainedPremium - premium);
+    baseToken.safeTransfer(msg.sender, obtainedPremium - premium);
} 
```

## [M-3] Complete DoS of every DVP's minting and burning, due to insufficient access controls within FeeManager::trackVaultFee.

### Summary
`FeeManager::trackVaultFee` has no access controls, so a malicious user can call it with malicious input, maximally inflating `vaultFeeAmounts` for any vault. This is a DoS for all minting and burning in the DVP associated with that vault.

### Vulnerability Details
`FeeManager::trackVaultFee` is an external function with improper access controls. It expects `msg.sender` to be the DVP for a vault but does not check that this is the case.

```solidity
function trackVaultFee(address vault, uint256 feeAmount) external { //@audit no access controls!
        // Check sender:
        IDVP dvp = IDVP(msg.sender);
        if (vault != dvp.vault()) {
            revert WrongVault();
        }

        vaultFeeAmounts[vault] += feeAmount;

        emit TransferVaultFee(vault, feeAmount);
    }
```

A malicious user can use a dummy contract that prevents the function from reverting, and provide a `feeAmount` that raises `vaultFeeAmounts[vault]` to `type(uint256).max`.

Example Dummy Contract that would work
To attack using the above contract, an attacker would simply deploy the decoy and call the `attack()` function with a vault and the FeeManager as parameters.

Then after this attack, whenever `DVP::_mint` or `DVP::_burn` is called, it calls `FeeManager::trackVaultFee()` to track the fees, but it will revert due to overflow when trying to increment `vaultFeeAmounts[vault]`.

### Impact
Complete DoS can be achieved for any DVP, at zero cost to the attacker.

### Code Snippet
https://github.com/sherlock-audit/2024-02-smilee-finance/blob/3241f1bf0c8e951a41dd2e51997f64ef3ec017bd/smilee-v2-contracts/src/FeeManager.sol#L218-L228

### Tool used
Manual Review

### Recommendation
Maintain a mapping (address to boolean) which stores active DVP addresses, and have an admin-function to set these when a new DVP is added. Then in `trackVaultFee`, revert if `msg.sender` maps to a false boolean in that mapping.





