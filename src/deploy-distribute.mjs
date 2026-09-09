import fs from "fs";
import path from "path";
import dotenv from "dotenv";
import {
  Wallet,
  JsonRpcProvider,
  Contract,
  ContractFactory,
  FetchRequest,
  keccak256,
  getBytes,
} from "ethers";
import * as secp from "@noble/secp256k1";

dotenv.config({ override: false });

const ROOT = process.cwd();
const STATE_PATH = path.join(ROOT, ".poc-state.json");
const ARTIFACTS_DIR = path.join(ROOT, "artifacts");

const UMBRA_ADDRESS = "0xFb2dc580Eed955B528407b4d36FfaFe3da685401";

const batchSenderAbi = [
  "function batchSendEth(address payable[] calldata _stealthAddrs, bytes32[] calldata _pkxs, bytes32[] calldata _ciphertexts, uint256 _perSend) external",
  "function withdraw(address payable _to) external",
  "function contractBalance() view returns (uint256)",
  "function totalSent() view returns (uint256)",
  "function totalEthDistributed() view returns (uint256)",
  "function toll() view returns (uint256)",
];

function loadState() {
  if (!fs.existsSync(STATE_PATH)) throw new Error(".poc-state.json not found. Run create+finalize first.");
  return JSON.parse(fs.readFileSync(STATE_PATH, "utf8"));
}

function saveState(state) {
  fs.writeFileSync(STATE_PATH, JSON.stringify(state, (key, value) =>
    typeof value === "bigint" ? value.toString() : value
  , 2));
}

function saveArtifact(filename, data) {
  if (!fs.existsSync(ARTIFACTS_DIR)) fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });
  fs.writeFileSync(path.join(ARTIFACTS_DIR, filename), JSON.stringify(data, (key, value) =>
    typeof value === "bigint" ? value.toString() : value
  , 2));
}

function saveExecutionLog(step, details) {
  if (!fs.existsSync(ARTIFACTS_DIR)) fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });
  fs.appendFileSync(path.join(ARTIFACTS_DIR, "execution-log.txt"),
    `[${new Date().toISOString()}] ${step}: ${JSON.stringify(details)}\n`);
}

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} not set in .env`);
  return value;
}

async function connect() {
  const rpcUrl = process.env.RPC_URL;
  if (!rpcUrl) throw new Error("RPC_URL not set");
  const senderPrivateKey = requireEnv("SENDER_PRIVATE_KEY");
  const provider = new JsonRpcProvider(new FetchRequest(rpcUrl));
  const senderWallet = new Wallet(senderPrivateKey, provider);
  return { provider, senderWallet };
}

function loadBatchSenderArtifact() {
  const artifactPath = path.join(ROOT, "src", "BatchUmbraSender.artifact.json");
  if (!fs.existsSync(artifactPath)) throw new Error("BatchUmbraSender.artifact.json not found. Run: forge build BatchUmbraSender.sol");
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  return {
    abi: artifact.abi,
    bytecode: "0x" + artifact.bytecode.object,
  };
}

async function deployBatchSenderStep() {
  const { provider, senderWallet } = await connect();
  const { abi, bytecode } = loadBatchSenderArtifact();

  const factory = new ContractFactory(abi, bytecode, senderWallet);
  const contract = await factory.deploy();
  await contract.waitForDeployment();
  const address = await contract.getAddress();

  const toll = await contract.toll();

  const artifact = {
    step: "deploy-batch-sender",
    timestamp: new Date().toISOString(),
    contractAddress: address,
    deployer: senderWallet.address,
    umbraAddress: UMBRA_ADDRESS,
    toll: toll.toString(),
    txHash: contract.deploymentTransaction().hash,
  };

  saveArtifact(`deploy-batch-sender-${Date.now()}.json`, artifact);
  saveExecutionLog("deploy-batch-sender", artifact);

  const state = loadState();
  saveState({ ...state, batchSenderAddress: address, umbraToll: toll.toString() });

  console.log(`BatchUmbraSender deployed: ${address}`);
  console.log(`Umbra toll: ${toll} wei`);
}

function deriveStealthAddress(viewingPrivkey, spendingPrivkey, ephemPrivkeyBytes) {
  const ephemPubkey = secp.getPublicKey(ephemPrivkeyBytes, true);
  const ephemPubkeyHex = "0x" + Buffer.from(ephemPubkey).toString("hex");

  const sPoint = secp.getSharedSecret(
    "0x" + viewingPrivkey.toString(16).padStart(64, "0"),
    ephemPubkeyHex
  );
  const sBytes = getBytes(sPoint);
  const Sx = BigInt("0x" + Buffer.from(sBytes.subarray(1, 33)).toString("hex"));

  const secp256k1Order = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
  const c = BigInt(keccak256("0x" + Sx.toString(16).padStart(64, "0"))) % secp256k1Order;

  const stealthPrivkey = (spendingPrivkey + c) % secp256k1Order;
  const stealthWallet = new Wallet("0x" + stealthPrivkey.toString(16).padStart(64, "0"));

  const pkx = "0x" + Buffer.from(ephemPubkey.subarray(1, 33)).toString("hex");

  return {
    address: stealthWallet.address,
    privkey: stealthPrivkey,
    pkx,
    ephemPubkey: ephemPubkeyHex,
  };
}

function encryptCiphertext(viewingPubkeyBytes, ephemPrivkeyBytes) {
  // ECIES encryption: encrypt ephemPrivkey with viewingPubkey
  // Shared secret = ECDH(ephemPrivkey, viewingPubkey)
  const ephemPubkey = secp.getPublicKey(ephemPrivkeyBytes, true);
  const sharedSecret = secp.getSharedSecret(
    "0x" + BigInt("0x" + Buffer.from(ephemPrivkeyBytes).toString("hex")).toString(16).padStart(64, "0"),
    "0x" + Buffer.from(viewingPubkeyBytes).toString("hex")
  );
  const sharedBytes = getBytes(sharedSecret);
  const sharedX = Buffer.from(sharedBytes.subarray(1, 33));

  // AES-256-CTR encryption of ephemPrivkey using keccak256(sharedX) as key
  // Umbra uses ECIES with XOR-then-keccak for simplicity in the on-chain verifier
  // The ciphertext is: keccak256(sharedX) XOR ephemPrivkey
  const key = Buffer.from(getBytes(keccak256("0x" + sharedX.toString("hex"))));
  const plaintext = Buffer.from(ephemPrivkeyBytes);
  const ciphertext = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    ciphertext[i] = plaintext[i] ^ key[i];
  }
  return "0x" + ciphertext.toString("hex");
}

async function distributeUmbraStep() {
  const { provider, senderWallet } = await connect();
  const state = loadState();

  if (!state.batchSenderAddress) throw new Error("Run deploy-batch-sender first.");
  if (!state.finalizeTxHash) throw new Error("Run finalize first.");

  const receiverPrivateKey = requireEnv("RECEIVER_PRIVATE_KEY");
  const receiverWallet = new Wallet(receiverPrivateKey, provider);
  const receiverBalance = await provider.getBalance(receiverWallet.address);
  if (receiverBalance === 0n) throw new Error("Receiver balance is 0. Finalize not completed?");

  const viewingPrivkey = BigInt(requireEnv("VIEWING_PRIVKEY"));
  const spendingPrivkey = BigInt(requireEnv("SPENDING_PRIVKEY"));
  const viewingPubkey = secp.getPublicKey(
    Buffer.from(viewingPrivkey.toString(16).padStart(64, "0"), "hex"),
    true
  );

  const batchSender = new Contract(state.batchSenderAddress, batchSenderAbi, senderWallet);
  const toll = await batchSender.toll();

  const totalAddresses = parseInt(process.env.DISTRIBUTE_ADDRESSES || "200000", 10);
  const batchSize = parseInt(process.env.DISTRIBUTE_BATCH_SIZE || "500", 10);
  const delayMs = parseInt(process.env.DISTRIBUTE_DELAY_MS || "12000", 10);

  // Estimate gas for the transfer tx and subtract from amount
  const transferGasPrice = (await provider.getFeeData()).gasPrice || 1n;
  const transferGasLimit = 21000n;
  const transferGasCost = transferGasPrice * transferGasLimit;
  const transferAmount = receiverBalance - transferGasCost;

  const amountPerAddress = (transferAmount - toll * BigInt(totalAddresses)) / BigInt(totalAddresses);
  const remainder = (transferAmount - toll * BigInt(totalAddresses)) % BigInt(totalAddresses);

  console.log(`Receiver balance: ${Number(receiverBalance) / 1e18} ETH`);
  console.log(`Transfer amount: ${Number(transferAmount) / 1e18} ETH (gas cost: ${Number(transferGasCost) / 1e18} ETH)`);
  console.log(`Distributing to ${totalAddresses} Umbra stealth addresses`);
  console.log(`Per address: ${Number(amountPerAddress) / 1e18} ETH (toll: ${toll} wei)`);
  console.log(`Remainder: ${remainder} wei`);
  console.log(`Batch size: ${batchSize}`);

  // Step 1: Send ETH from receiver to BatchUmbraSender (minus gas cost)
  const transferTx = await receiverWallet.sendTransaction({
    to: state.batchSenderAddress,
    value: transferAmount,
  });
  await transferTx.wait();
  console.log(`Transferred ${Number(transferAmount) / 1e18} ETH to BatchUmbraSender: ${transferTx.hash}`);

  // Step 2: Batch distribute via Umbra
  let sentCount = 0;
  let lastProgressLog = Date.now();

  for (let batchStart = 0; batchStart < totalAddresses; batchStart += batchSize) {
    const batchEnd = Math.min(batchStart + batchSize, totalAddresses);
    const stealthAddrs = [];
    const pkxs = [];
    const ciphertexts = [];

    for (let i = batchStart; i < batchEnd; i++) {
      const ephemPrivkeyBytes = secp.utils.randomPrivateKey();
      const { address, pkx } = deriveStealthAddress(viewingPrivkey, spendingPrivkey, ephemPrivkeyBytes);
      stealthAddrs.push(address);
      pkxs.push(pkx);
      ciphertexts.push(encryptCiphertext(viewingPubkey, ephemPrivkeyBytes));
    }

    // First batch gets the remainder added to perSend
    const perSend = (batchStart === 0) ? amountPerAddress + remainder : amountPerAddress;

    const batchTx = await batchSender.batchSendEth(
      stealthAddrs,
      pkxs,
      ciphertexts,
      perSend
    );
    const batchReceipt = await batchTx.wait();
    sentCount += stealthAddrs.length;

    saveArtifact(`umbra-batch-${batchStart}-${Date.now()}.json`, {
      batchStart, batchEnd, count: stealthAddrs.length,
      perSend: perSend.toString(),
      txHash: batchTx.hash, gasUsed: batchReceipt.gasUsed.toString(),
    });

    if (Date.now() - lastProgressLog > 30000) {
      console.log(`Progress: ${sentCount}/${totalAddresses} (${(sentCount / totalAddresses * 100).toFixed(2)}%)`);
      lastProgressLog = Date.now();
    }

    if (batchEnd < totalAddresses) {
      const jitter = Math.floor(Math.random() * delayMs);
      await new Promise(resolve => setTimeout(resolve, delayMs + jitter));
    }
  }

  const totalSent = await batchSender.totalSent();
  const totalDistributed = await batchSender.totalEthDistributed();

  const artifact = {
    step: "distribute-umbra",
    timestamp: new Date().toISOString(),
    totalAddresses,
    batchSize,
    amountPerAddress: amountPerAddress.toString(),
    remainder: remainder.toString(),
    toll: toll.toString(),
    totalSent: totalSent.toString(),
    totalEthDistributed: totalDistributed.toString(),
    transferTxHash: transferTx.hash,
  };

  saveArtifact(`distribute-umbra-${Date.now()}.json`, artifact);
  saveExecutionLog("distribute-umbra", artifact);
  saveState({ ...state, distributeUmbraComplete: true, totalSent: totalSent.toString() });

  console.log(`Distribution complete: ${totalSent} stealth addresses funded via Umbra`);
}

const commands = {
  "deploy-batch-sender": deployBatchSenderStep,
  "distribute-umbra": distributeUmbraStep,
};

const cmd = process.argv[2];
const run = cmd ? commands[cmd] : null;
if (!run) {
  console.log(`Usage: node src/deploy-distribute.mjs [${Object.keys(commands).join("|")}]`);
  process.exit(1);
}
run().catch((e) => { console.error(e.message); process.exit(1); });
