import dotenv from "dotenv";
import { JsonRpcProvider, Contract, getAddress, FetchRequest, keccak256, AbiCoder, getBytes } from "ethers";

dotenv.config({ override: false });

const DEFAULT_SYSTEM_CONFIG = "0x229047fed2591dbec1eF1118d64F7aF3dB9EB290";

const systemConfigAbi = [
  "function optimismPortal() view returns (address)",
  "function l2ChainId() view returns (uint256)"
];

const portalAbi = [
  "function version() view returns (string)",
  "function disputeGameFactory() view returns (address)",
  "function anchorStateRegistry() view returns (address)",
  "function proofMaturityDelaySeconds() view returns (uint256)",
  "function disputeGameFinalityDelaySeconds() view returns (uint256)",
  "function ethLockbox() view returns (address)",
  "function guardian() view returns (address)",
  "function systemConfig() view returns (address)"
];

const asrAbi = [
  "function disputeGameFactory() view returns (address)",
  "function respectedGameType() view returns (uint32)",
  "function getAnchorRoot() view returns (bytes32, uint256)",
  "function disputeGameFinalityDelaySeconds() view returns (uint256)",
  "function anchorGame() view returns (address)"
];

const dgfAbi = [
  "function gameCount() view returns (uint256)",
  "function gameAtIndex(uint256 _index) view returns (uint32 gameType, uint64 timestamp, address proxy)",
  "function initBonds(uint32 _gameType) view returns (uint256)"
];

const superchainConfigAbi = [
  "function paused(address _identifier) view returns (bool)"
];

const faultDisputeGameAbi = [
  "function rootClaim() view returns (bytes32)",
  "function status() view returns (uint8)",
  "function createdAt() view returns (uint64)",
  "function l2BlockNumber() view returns (uint256)",
  "function maxClockDuration() view returns (uint64)",
  "function resolvedAt() view returns (uint64)"
];

async function main() {
  const rpcUrl = process.env.RPC_URL;
  if (!rpcUrl) throw new Error("RPC_URL not set");
  console.log(`RPC: ${rpcUrl}`);

  const provider = new JsonRpcProvider(new FetchRequest(rpcUrl));
  const network = await provider.getNetwork();
  console.log(`Chain ID: ${network.chainId}`);
  console.log(`Block: ${await provider.getBlockNumber()}`);
  console.log("");

  const systemConfigAddress = getAddress(process.env.SYSTEM_CONFIG || DEFAULT_SYSTEM_CONFIG);
  const systemConfig = new Contract(systemConfigAddress, systemConfigAbi, provider);
  const portalAddress = getAddress(await systemConfig.optimismPortal());
  const portal = new Contract(portalAddress, portalAbi, provider);
  const asrAddress = getAddress(await portal.anchorStateRegistry());
  const asr = new Contract(asrAddress, asrAbi, provider);
  const dgfAddress = getAddress(await asr.disputeGameFactory());
  const dgf = new Contract(dgfAddress, dgfAbi, provider);
  const lockboxAddress = getAddress(await portal.ethLockbox());
  const guardianAddress = await portal.guardian();

  const version = await portal.version();
  const gameType = await asr.respectedGameType();
  const initBond = await dgf.initBonds(gameType);
  const proofMaturity = await portal.proofMaturityDelaySeconds();
  const finalityDelay = await portal.disputeGameFinalityDelaySeconds();
  const [anchorRoot, anchorSeq] = await asr.getAnchorRoot();
  const anchorGame = await asr.anchorGame();
  const gameCount = await dgf.gameCount();
  const lockboxBalance = await provider.getBalance(lockboxAddress);

  console.log("=== Contract Addresses ===");
  console.log(`SystemConfig:       ${systemConfigAddress}`);
  console.log(`OptimismPortal2:    ${portalAddress}`);
  console.log(`AnchorStateRegistry:${asrAddress}`);
  console.log(`DisputeGameFactory: ${dgfAddress}`);
  console.log(`ETHLockbox:         ${lockboxAddress}`);
  console.log(`Guardian:           ${guardianAddress}`);
  console.log("");

  console.log("=== Portal ===");
  console.log(`Version:            ${version}`);
  console.log("");

  console.log("=== Parameters ===");
  console.log(`RespectedGameType:  ${gameType}`);
  console.log(`InitBond:           ${initBond} wei (${Number(initBond) / 1e18} ETH)`);
  console.log(`ProofMaturityDelay: ${proofMaturity} s (${Number(proofMaturity) / 86400} days)`);
  console.log(`FinalityDelay:      ${finalityDelay} s (${Number(finalityDelay) / 86400} days)`);
  console.log("");

  console.log("=== Anchor State ===");
  console.log(`AnchorRoot:         ${anchorRoot}`);
  console.log(`AnchorSeq:          ${anchorSeq}`);
  console.log(`AnchorGame:         ${anchorGame}`);
  console.log("");

  console.log("=== DisputeGameFactory ===");
  console.log(`GameCount:          ${gameCount}`);
  console.log("");

  console.log("=== ETHLockbox ===");
  console.log(`Balance:            ${lockboxBalance} wei (${Number(lockboxBalance) / 1e18} ETH)`);
  console.log("");

  if (gameCount > 0n) {
    console.log("=== Latest Games ===");
    const start = gameCount > 5n ? gameCount - 5n : 0n;
    for (let i = start; i < gameCount; i++) {
      const [gType, ts, proxy] = await dgf.gameAtIndex(i);
      const game = new Contract(proxy, faultDisputeGameAbi, provider);
      const status = await game.status();
      const createdAt = await game.createdAt();
      const l2Block = await game.l2BlockNumber();
      const rootClaim = await game.rootClaim();
      const maxClock = await game.maxClockDuration();
      let resolvedAt = 0n;
      try { resolvedAt = await game.resolvedAt(); } catch {}
      const statusNames = ["IN_PROGRESS", "CHALLENGER_WINS", "DEFENDER_WINS"];
      console.log(`  Game #${i}: type=${gType} proxy=${proxy} status=${statusNames[Number(status)] || status}`);
      console.log(`    createdAt=${createdAt} l2Block=${l2Block} maxClock=${maxClock}s resolvedAt=${resolvedAt}`);
      console.log(`    rootClaim=${rootClaim}`);
    }
  }

  console.log("");
  console.log("=== SuperchainConfig Paused State ===");
  const superchainConfigAddress = getAddress(process.env.SUPERCHAIN_CONFIG_ADDRESS || "0x95703e0982140D16f8ebA6d158FccEde42f04a4C");
  const superchainConfig = new Contract(superchainConfigAddress, superchainConfigAbi, provider);
  const portalPaused = await superchainConfig.paused(portalAddress);
  const zeroPaused = await superchainConfig.paused("0x0000000000000000000000000000000000000000");
  const lockboxPaused = await superchainConfig.paused(lockboxAddress);
  console.log(`Portal paused:   ${portalPaused}`);
  console.log(`Global paused:   ${zeroPaused}`);
  console.log(`Lockbox paused:  ${lockboxPaused}`);

  console.log("");
  console.log("=== Read-only check complete ===");
}

main().catch(e => { console.error(e.message); process.exit(1); });
