import fs from 'fs';
import path from 'path';
import http from 'http';
import os from 'os';

const ROOT = process.cwd();
const ENV_PATH = path.join(ROOT, '.env');
const SRC_DIR = path.join(ROOT, 'src');
const PKG_PATH = path.join(ROOT, 'package.json');
const STATE_PATH = path.join(ROOT, '.poc-state.json');
const CONFIG_PATH = path.join(ROOT, 'config.toml');
const NETHERMIND_LOG = 'E:\\eth\\el\\nethermind_db\\nethermind_db\\mainnet\\logs\\mainnet.log';

const PUBLIC_RPC_HINTS = [
  'alchemy', 'infura', 'quicknode', 'ankr', 'cloudflare', 'pokt',
  'chainstack', 'blastapi', 'llamarpc', 'drpc', '1rpc', 'tenderly', 'drpc.org', 'getblock.io'
];

const PUBLIC_RPC_URLS = [
  'https://mainnet.infura.io', 'https://eth-mainnet.g.alchemy.com',
  'https://rpc.ankr.com/eth', 'https://eth.llamarpc.com',
  'https://cloudflare-eth.com', 'https://eth.drpc.org'
];

const EXFIL_HINTS = ['discord.com', 'telegram.org', 'hooks.slack.com', 'api.ipify.org', 'icanhazip.com', 'checkip.amazonaws.com', 'esm.sh', 'unpkg.com', 'jsdelivr.net'];

const KEY_LIKE_RE = /(?:private|secret|sender|receiv|spending|viewing|spend|view).*key|privkey/i;
const SENSITIVE_LOG_RE = /console\.(?:log|error|warn|info)\(.*(?:privateKey|privkey|secret|SENDER_PRIVATE_KEY|RECEIVER_PRIVATE_KEY|VIEWING_PRIVKEY|SPENDING_PRIVKEY|private[_-]?key|\bprocess\.env\b)/i;

let failureCount = 0;

function fail(msg) { failureCount++; console.log(`[FAIL] ${msg}`); }
function pass(msg) { console.log(`[PASS] ${msg}`); }
function info(msg) { console.log(`[INFO] ${msg}`); }

function isAllowedLocalHttpUrl(value) {
  try {
    const url = new URL(value);
    if (url.protocol !== 'http:' || url.username || url.password) return false;
    const host = url.hostname.toLowerCase().replace(/[\[\]]/g, '');
    if (host === 'localhost' || host === '127.0.0.1' || host === '::1') return true;

    const octets = host.split('.');
    const validIpv4 = octets.length === 4 && octets.every(o => /^\d{1,3}$/.test(o) && Number(o) <= 255);
    if (!validIpv4) return false;
    const first = Number(octets[0]);
    const second = Number(octets[1]);
    return first === 10 || (first === 192 && second === 168) || (first === 172 && second >= 16 && second <= 31);
  } catch {
    return false;
  }
}

function checkEnv() {
  if (!fs.existsSync(ENV_PATH)) { fail('.env not found'); return; }
  const env = fs.readFileSync(ENV_PATH, 'utf8');

  const rpcUrl = env.match(/^RPC_URL\s*=\s*(.+)$/m)?.[1]?.trim() || '';
  const ethRpcUrl = env.match(/^ETH_RPC_URL\s*=\s*(.+)$/m)?.[1]?.trim() || '';

  for (const [name, url] of [['RPC_URL', rpcUrl], ['ETH_RPC_URL', ethRpcUrl]]) {
    if (!isAllowedLocalHttpUrl(url)) {
      fail(`${name} is not a valid local HTTP endpoint: ${url || '<missing>'}`);
      continue;
    }

    const host = new URL(url).hostname.toLowerCase();
    if (host === '127.0.0.1' || host === 'localhost' || host === '::1') {
      pass(`${name} is loopback: ${url}`);
    } else {
      pass(`${name} is local-network: ${url}`);
      info(`${name} on 127.0.0.1 is more private; packets stay on this host`);
    }
  }

  const publicUrl = PUBLIC_RPC_URLS.find(u => env.includes(u));
  if (publicUrl) fail(`Public RPC URL found in .env: ${publicUrl}`);
  else info('No listed public RPC endpoints found in .env');

  const publicHint = PUBLIC_RPC_HINTS.find(h => env.toLowerCase().includes(h.toLowerCase()));
  if (publicHint) fail(`Public RPC provider name found in .env: ${publicHint}`);
  else info('No listed public RPC provider names found in .env');
}

function checkSourceForLeaks() {
  if (!fs.existsSync(SRC_DIR)) { fail('src directory not found'); return; }
  const files = fs.readdirSync(SRC_DIR).filter(f => f.endsWith('.js'));
  let hasKeys = false;
  let hasLogKeys = false;
  let hasFallback = false;
  let hasExfil = false;

  for (const f of files) {
    const p = path.join(SRC_DIR, f);
    const content = fs.readFileSync(p, 'utf8');

    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (KEY_LIKE_RE.test(line) && /0x[a-fA-F0-9]{64}/.test(line)) {
        hasKeys = true;
        fail(`Possible hardcoded key near line ${i + 1} in ${f}`);
      }
      if (SENSITIVE_LOG_RE.test(line)) {
        hasLogKeys = true;
        fail(`Possible secret logging near line ${i + 1} in ${f}`);
      }
      if (/(?:\|\||\?\?)\s*['"](?:https?:\/\/)/.test(line) || /['"](?:https?:\/\/)[^'"]+['"]\s*\|\|\s*process\.env/.test(line)) {
        hasFallback = true;
        fail(`Possible RPC fallback URL near line ${i + 1} in ${f}`);
      }
      if (/(?:fetch\(|https\.request|import\(['"])\s*(?:['"]|`)https:\/\/(?!(?:127\.0\.0\.1|localhost|192\.168|10\.|172\.(?:1[6-9]|2\d|3[01])\.))/.test(line)) {
        hasExfil = true;
        fail(`Possible external exfiltration/fetch near line ${i + 1} in ${f}`);
      }
    }

    const publicUrl = PUBLIC_RPC_URLS.find(u => content.includes(u));
    if (publicUrl) fail(`Public RPC URL in ${f}: ${publicUrl}`);
    const publicHint = PUBLIC_RPC_HINTS.find(h => content.toLowerCase().includes(h.toLowerCase()));
    if (publicHint) fail(`Public RPC provider in ${f}: ${publicHint}`);
    const exfilHint = EXFIL_HINTS.find(h => content.toLowerCase().includes(h.toLowerCase()));
    if (exfilHint) fail(`Possible exfiltration target in ${f}: ${exfilHint}`);
  }

  if (!hasKeys) pass('No obvious hardcoded keys in src/*.js');
  if (!hasLogKeys) pass('No obvious secret logging in src/*.js');
  if (!hasFallback) pass('No obvious public RPC fallbacks in src/*.js');
  if (!hasExfil) pass('No external fetch/POST exfiltration patterns in src/*.js');
}

function checkConfigToml() {
  if (!fs.existsSync(CONFIG_PATH)) { info('config.toml not found, skipping'); return; }
  const content = fs.readFileSync(CONFIG_PATH, 'utf8');
  const url = content.match(/(?:rpc_url|url)\s*=\s*["']([^"']+)["']/i)?.[1] || '';
  if (url) {
    if (isAllowedLocalHttpUrl(url)) pass(`config.toml rpc_url is local: ${url}`);
    else fail(`config.toml rpc_url is not a valid local HTTP endpoint: ${url}`);
  }
  const publicHint = PUBLIC_RPC_HINTS.find(h => content.toLowerCase().includes(h.toLowerCase()));
  if (publicHint) fail(`Public RPC provider in config.toml: ${publicHint}`);
  else pass('No public RPC provider names in config.toml');
}

function checkPocState() {
  if (!fs.existsSync(STATE_PATH)) { info('.poc-state.json not found, skipping'); return; }

  let state;
  try {
    state = JSON.parse(fs.readFileSync(STATE_PATH, 'utf8'));
  } catch (e) {
    fail(`.poc-state.json is not valid JSON: ${e.message}`);
    return;
  }

  function containsSecret(value, key = '') {
    if (/(?:private|secret|privkey)/i.test(key)) return value !== null && value !== undefined && value !== '';
    if (Array.isArray(value)) return value.some(item => containsSecret(item, key));
    if (value && typeof value === 'object') {
      return Object.entries(value).some(([childKey, childValue]) => containsSecret(childValue, childKey));
    }
    return false;
  }

  if (containsSecret(state)) fail('.poc-state.json contains a secret-named field');
  else pass('.poc-state.json contains no secret-named fields');
}

function checkPackageJson() {
  if (!fs.existsSync(PKG_PATH)) { fail('package.json not found'); return; }
  const pkg = JSON.parse(fs.readFileSync(PKG_PATH, 'utf8'));
  if (pkg.private !== true) info('package.json is not marked "private": true (npm publish risk)');
  else pass('package.json is marked private');

  const scripts = JSON.stringify(pkg.scripts || {});
  const publicUrl = PUBLIC_RPC_URLS.find(u => scripts.includes(u));
  if (publicUrl) fail(`Public RPC URL in package.json scripts: ${publicUrl}`);
  else pass('No public RPC endpoints in package.json scripts');
}

function checkNetworkInterfacesAndIp() {
  try {
    const ifaces = os.networkInterfaces();
    const adapters = Object.keys(ifaces);
    const vpnLike = adapters.filter(a => /proton|vpn|wireguard|tun|tap|vEthernet/i.test(a));
    if (vpnLike.length) pass(`VPN-like adapter found: ${vpnLike.join(', ')}`);
    else info('No obvious VPN adapter detected. Verify VPN is active.');

    let hasPublicInterface = false;
    for (const [name, addrs] of Object.entries(ifaces)) {
      for (const a of addrs) {
        if (a.internal) continue;
        const ip = a.address;
        const isLocal = ip.match(/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|fe80:|::1$)/i);
        if (!isLocal) {
          hasPublicInterface = true;
          info(`Public IP on adapter ${name}: ${ip}`);
        }
      }
    }
    if (!hasPublicInterface) pass('No public IP directly on host adapters (good if VPN is active)');
    else info('A public IP is directly assigned to a host adapter; verify it is the VPN tunnel, not ISP');
  } catch (e) {
    fail(`Network interface check failed: ${e.message}`);
  }
}

function checkNodeExternalIp() {
  if (!fs.existsSync(NETHERMIND_LOG)) { info('Nethermind log not found, skipping External IP check'); return; }
  const content = fs.readFileSync(NETHERMIND_LOG, 'utf8');
  const match = content.match(/External\s+IP\s*:\s*([\d.]+)/i);
  if (!match) { info('No External IP found in Nethermind log'); return; }
  const ip = match[1];
  if (ip.match(/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)/)) {
    pass(`Nethermind External IP is private: ${ip}`);
  } else {
    info(`Nethermind External IP is public: ${ip} — verify this is your VPN exit, not ISP`);
  }
}

function checkLocalNode() {
  return new Promise((resolve) => {
    let rpcUrl = 'http://127.0.0.1:8545';
    if (fs.existsSync(ENV_PATH)) {
      const env = fs.readFileSync(ENV_PATH, 'utf8');
      rpcUrl = env.match(/^RPC_URL\s*=\s*(.+)$/m)?.[1]?.trim() || rpcUrl;
    }
    let u;
    try { u = new URL(rpcUrl); } catch {
      fail(`Invalid RPC_URL in .env: ${rpcUrl}`);
      return resolve();
    }
    const options = {
      hostname: u.hostname,
      port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname || '/',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (res.statusCode < 200 || res.statusCode >= 300) {
            throw new Error(`HTTP ${res.statusCode}`);
          }
          if (json.jsonrpc !== '2.0' || json.id !== 1 || json.error || typeof json.result !== 'string' || !/^0x[0-9a-f]+$/i.test(json.result)) {
            throw new Error('invalid JSON-RPC eth_chainId response');
          }
          const chainId = Number.parseInt(json.result, 16);
          if (!Number.isSafeInteger(chainId)) throw new Error('invalid chain ID');
          if (chainId === 1) pass(`Node reachable at ${u.host}, chainId=${chainId} (Mainnet)`);
          else if (chainId === 10) pass(`Node reachable at ${u.host}, chainId=${chainId} (OP Mainnet)`);
          else pass(`Node reachable at ${u.host}, chainId=${chainId}`);
        } catch (e) {
          fail(`Node responded with an invalid JSON-RPC response: ${e.message}`);
        }
        resolve();
      });
    });

    req.setTimeout(10000, () => req.destroy(new Error('request timed out')));
    req.on('error', (e) => {
      fail(`Node not reachable at ${u.host}: ${e.message}`);
      resolve();
    });

    req.write(JSON.stringify({ jsonrpc: '2.0', method: 'eth_chainId', params: [], id: 1 }));
    req.end();
  });
}

function checkCommandLeaks() {
  const home = os.homedir();

  const gitignorePath = path.join(ROOT, '.gitignore');
  if (fs.existsSync(gitignorePath)) {
    const gitignore = fs.readFileSync(gitignorePath, 'utf8');
    const required = ['.env', '.poc-state.json', 'node_modules'];
    for (const r of required) {
      if (gitignore.split(/\r?\n/).some(l => l.trim() === r || l.trim().startsWith(`${r}/`))) {
        pass(`.gitignore blocks ${r}`);
      } else {
        fail(`.gitignore does NOT block ${r} — risk of accidental commit`);
      }
    }
  } else {
    fail('.gitignore not found — .env may be committed');
  }

  const psHistory = path.join(home, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine', 'ConsoleHost_history.txt');
  if (fs.existsSync(psHistory)) {
    const h = fs.readFileSync(psHistory, 'utf8');
    const hasPrivateKeyValue = /(?:SENDER_PRIVATE_KEY|RECEIVER_PRIVATE_KEY|VIEWING_PRIVKEY|SPENDING_PRIVKEY|PRIVATE_KEY)\s*(?:=|:|\s)\s*["']?0x[a-fA-F0-9]{64}\b/i.test(h);
    if (hasPrivateKeyValue) {
      fail('PowerShell history contains a private-key value');
    } else {
      pass('PowerShell history does not contain private-key values');
    }
    if (/RPC_URL|ETH_RPC_URL/.test(h)) {
      info('PowerShell history contains RPC_URL/ETH_RPC_URL strings (acceptable if not secret)');
    }
  } else {
    info('PowerShell history not found');
  }

  const pkg = fs.existsSync(PKG_PATH) ? JSON.parse(fs.readFileSync(PKG_PATH, 'utf8')) : {};
  const scripts = JSON.stringify(pkg.scripts || {});
  if (/PRIVATE_KEY|SECRET|API_KEY|0x[a-fA-F0-9]{64}/i.test(scripts)) {
    fail('package.json scripts may pass secrets on command line (visible in shell history / process list)');
  } else {
    pass('package.json scripts do not pass obvious secrets on command line');
  }

  if (fs.existsSync(ENV_PATH)) {
    const env = fs.readFileSync(ENV_PATH, 'utf8');
    if (env.split(/\r?\n/).some(l => l.match(/^(SENDER_PRIVATE_KEY|RECEIVER_PRIVATE_KEY|VIEWING_PRIVKEY|SPENDING_PRIVKEY)\s*=\s*.+/))) {
      info('.env contains configured secret variables; verify they are valid test credentials and remain local');
    }
  }
}

function checkBinaryLeftovers() {
  const home = os.homedir();
  const dumpDirs = [
    path.join(home, 'AppData', 'Local', 'CrashDumps'),
    'C:\\Windows\\Minidump',
    'C:\\Windows\\LiveKernelReports',
    path.join(home, 'AppData', 'Local', 'Temp')
  ];

  let found = false;
  for (const d of dumpDirs) {
    if (!fs.existsSync(d)) continue;
    try {
      const files = fs.readdirSync(d);
      const suspicious = files.filter(f => /node|nethermind|poc/i.test(f) && (f.endsWith('.dmp') || f.endsWith('.mdmp') || f.endsWith('.tmp') || f.endsWith('.log')));
      for (const f of suspicious) {
        found = true;
        info(`Possible binary/leftover: ${path.join(d, f)}`);
      }
    } catch {}
  }
  if (!found) pass('No obvious node/nethermind/poc crash dumps or temp leftovers');
}

function checkBackupFiles() {
  if (!fs.existsSync(ROOT)) return;
  const files = fs.readdirSync(ROOT);
  const backups = files.filter(f => /\.(bak|tmp|swp|~|orig|old)$/i.test(f));
  if (backups.length) {
    for (const b of backups) info(`Backup/temp file in project: ${b}`);
  } else {
    pass('No backup/temp files in project root');
  }
}

async function main() {
  console.log('=== OPSEC / setup check ===');
  checkEnv();
  checkSourceForLeaks();
  checkConfigToml();
  checkPocState();
  checkPackageJson();
  checkNetworkInterfacesAndIp();
  checkNodeExternalIp();
  checkCommandLeaks();
  checkBinaryLeftovers();
  checkBackupFiles();
  await checkLocalNode();
  console.log(`=== done: ${failureCount} failure(s) ===`);
  if (failureCount > 0) process.exitCode = 1;
}

main().catch((e) => {
  fail(`Checker error: ${e.message}`);
  process.exitCode = 1;
});
