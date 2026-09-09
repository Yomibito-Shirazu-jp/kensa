# Optimism PoC — Trust Gap + LagoonFreeChain

## Overview

Proof-of-concept demonstrating that a fabricated L2 state root can be promoted to the canonical anchor on L1 without executing or reproducing any L2 state. The attack exploits a structural trust gap in the OP Stack dispute system combined with permissionless anchor promotion and Guardian limitations.

## Repository Structure

```
.
├── test/
│   └── LagoonFreeChain.t.sol   # Foundry PoC — 8 tests, all passing on mainnet fork
├── findings/
│   ├── FIND-001-sdm-verify-refund-trust-gap.md      # Core: Trust Gap vulnerability
│   ├── FIND-008-feevault-zero-recipient-guard-gap.md  # Fee vault recipient guard gap
│   ├── FIND-009-l1-fullchain-fabricated-root-to-lockbox-drain.md  # Full-chain drain path
│   └── FIND-010-guardian-cannot-unwind-poisoned-anchor.md  # Guardian cannot fix poisoned anchor
├── docs/
│   ├── MALICIOUS_SEQUENCER.md   # Parameter/attack surface analysis (T0-T4)
│   ├── EVIDENCE_CHAIN.md        # Code → state-transition → guard-limit evidence
│   └── SUBMISSION.md            # Full submission document
├── mainnet_damage.py            # Damage ceiling calculator & TX executor
├── foundry.toml                 # Foundry configuration
├── run.sh                       # Test runner script
└── .gitignore
```

## Prerequisites

- [Foundry](https://book.getfoundry.sh/) (forge, cast, anvil)
- Python 3.10+ with web3.py (for `mainnet_damage.py`)
- An Ethereum L1 full node (local or remote RPC)

## Quick Start

### 1. Start anvil (forking from local L1 node)

```bash
anvil --fork-url http://<L1_NODE_IP>:8545 --host 0.0.0.0 --port 8545
```

### 2. Run the PoC tests

```bash
export ETH_RPC_URL=http://127.0.0.1:8545
forge test --match-contract LagoonFreeChain -vvv
```

Or use the included script:

```bash
./run.sh
```

### 3. Run the damage calculator

```bash
pip install web3
python mainnet_damage.py --rpc http://127.0.0.1:8545
```

## Test Results (8/8 PASS)

| Test | Description |
|---|---|
| `test_0_liveParams` | Verifies live mainnet parameters (chainid, lockbox balance, initBond, delays) |
| `test_A_inventedRootBecomesCanonical` | Invented root passes `isGameClaimValid` without any L2 computation |
| `test_B_forgedProofPaysOut` | Forged output root extracts 10 ETH from ETHLockbox |
| `test_C_drainEntireLockbox` | Single withdrawal drains entire lockbox balance (~190,713 ETH) |
| `test_D_guardianPauseBlocks` | Guardian pause blocks payout (temporary) |
| `test_E_pauseExpiryReopens` | Pause auto-expires after 91 days, payout resumes |
| `test_F_poisonedAnchorSurvivesBlacklist` | Guardian blacklist cannot unwind poisoned anchor |
| `test_G_rootPoisonAmplifiesRecovery` | Absurd l2SequenceNumber halts all future honest games |

## Key Parameters (measured on mainnet fork)

| Parameter | Value |
|---|---|
| Chain ID | 1 (Ethereum mainnet) |
| ETHLockbox balance | 190,713 ETH |
| initBond | 0.08 ETH |
| proofMaturityDelay | 7 days (604,800 s) |
| disputeGameFinalityDelay | 3.5 days (302,400 s) |
| respectedGameType | 8 |

## Attack Flow Summary

1. **Attacker** creates a dispute game with a fabricated root (cost: 0.08 ETH bond)
2. No challenger appears → game resolves as DEFENDER_WINS (3.5 days)
3. `setAnchorState()` is called (permissionless) → fabricated root becomes canonical
4. Guardian can blacklist the game or pause the portal, but **cannot unwind the anchor**
5. After proof maturity delay (7 days), withdrawals against the fabricated root can finalize
6. With `l2SequenceNumber` set to an absurd value, all future honest games are blocked

## License

MIT
