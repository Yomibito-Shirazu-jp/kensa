---
id: FIND-009
phase: exploit
status: final
tier: CONFIRMED
gate: [cwe_id, cvss_score, evidence, attck_id, poc, impact]
depends_on: [exploit/findings/FIND-001-sdm-verify-refund-trust-gap.md]
produces: [audit-submission/SUBMISSION.md, report/technical-report.md]
---

# Finding: every L1 contract gate from a fabricated output root to an ETHLockbox payout is satisfiable by an unprivileged EOA for 0.08 ETH

## Overview

| Field | Value |
|-------|-------|
| **CWE** | CWE-345 — Insufficient Verification of Data Authenticity |
| **CVSS** | 0.0 as an independent finding — see the severity note |
| **Severity** | Informational alone; the L1 half of a Critical chain when combined with FIND-001/FIND-002 |
| **Tier** | `[CONFIRMED]` for what it states: the L1 path completes end to end on production bytecode |
| **Feasibility** | `true` — executed. `false` for a live loss today, because step 3 requires the absence of a challenger |
| **ATT&CK ID** | T1565.001 |
| **Component** | `OptimismPortal2` 5.6.1, `DisputeGameFactory`, `FaultDisputeGame`, `AnchorStateRegistry`, `ETHLockbox` — Ethereum mainnet, block 25,676,425 |
| **Requires** | Neither Lagoon nor SDM. No privilege. 0.08 ETH |

## Description

The complete L1 withdrawal path was executed against the production OP Mainnet deployment on a pinned
mainnet fork. A withdrawal whose output root is derived from nothing traverses every stage and removes ETH
from the live `ETHLockbox`:

```
create game (fabricated root)  ->  resolve DEFENDER_WINS  ->  prove  ->  finalize  ->  ETH received
```

Each gate and the reason it passes:

1. **`DisputeGameFactory.create`** stores `rootClaim` without examining it. The only constraint on caller
   input is `FaultDisputeGame.initialize`'s `l2BlockNumber() > anchor.l2SequenceNumber`.
2. **`FaultDisputeGame.resolve`** at `:717` sets `DEFENDER_WINS` when `claimData[0].counteredBy == address(0)`.
   After `maxClockDuration` (302,400 s), `resolveClaim(0, 0)` closes the root subgame uncountered.
3. **`proveWithdrawalTransaction`** compares `rootClaim` against `Hashing.hashOutputRootProof(_outputRootProof)`
   where `_outputRootProof` is a caller argument, then verifies the storage proof against
   `_outputRootProof.messagePasserStorageRoot` — a field of that same struct. Both sides originate with the
   prover; `stateRoot` and `latestBlockhash` are never compared to anything.
4. **`isGameClaimValid`** applies four formal checks — proper, respected, finalized, `DEFENDER_WINS` — and
   never inspects the claim. The contract documents this itself at `AnchorStateRegistry.sol:264`.
5. **`ETHLockbox.unlockETH`** bounds the amount only by `address(this).balance` (`:165`). No per-chain ledger.

## Executed demonstration

`audit-submission/L1FullChain.t.sol`, 2026-08-04, Ethereum mainnet fork at block 25,676,425.
Logs `[EVD-045]`, `[EVD-046]`; harness `[EVD-047]`.

```
portal 0xbEb5Fc579115071764c7423A4f12eDde41f106Ed  version 5.6.1  paused false
dgf    0xe5965Ab5962eDc7477C8520243A95517CD252fA9
asr    0x23B2C62946350F4246f9f9D027e071f0264FD113
lockbox 0x322b47Ff1FA8D5611F761e3E275C45B71b294D43   balance 199,815.510843788787124109 ETH
respectedGameType 8 (CANNON_KONA, non-super)   initBonds(8) 0.08 ETH   anchor l2Seq 154,789,750
maxClockDuration 302400   disputeGameFinalityDelay 302400   proofMaturityDelay 604800

run A  gained 1000000000000000000 wei              lockbox drained 1000000000000000000
run B  gained 199815510843528787124109 wei         lockbox after 0
2 passed; 0 failed
```

Every address was derived on-chain from `SystemConfig.optimismPortal()` downward; only the `SystemConfig`
address is an input, and it is overridable.

**Cheatcode inventory — none touches the trust boundary:** `createSelectFork` (state selection), `deal`
(bond + gas), `warp`/`roll` (advance past the protocol's own 3.5 d + 3.5 d + 7 d delays), `startPrank`
(ordinary EOA). **No `vm.store`, no `vm.mockCall`, no `vm.etch`.** `provenWithdrawals` is populated by the
portal's own `proveWithdrawalTransaction` and the game status by the game's own `resolve()`. This is the
material difference from the harnesses killed in VERIF-001 and VERIF-002, which seeded `provenWithdrawals`
with `vm.store` and mocked `isGameClaimValid`.

## The single off-chain dependency

Step 2 (resolution) is the only step that is not a contract property. On the fork no `op-challenger` runs,
so the game is uncountered. On mainnet today a challenger re-derives the output root, disagrees with a
fabricated one, counters, and the game resolves `CHALLENGER_WINS` — the bond is forfeited and nothing pays
out. `test_control_finalizeReverts_whenClaimNotValid` asserts that boundary in the same file.

## Impact

Alone: none realised, which is why the standalone severity is informational and no live loss is claimed.

Combined: this is the L1 half of a Critical chain. FIND-001 records that the SDM post-exec Verify path
adopts a producer-declared refund under a magnitude-only bound without recomputation, and FIND-002 records
that the fault-proof program consumes the same declared value through the same executor. Under those two,
an honest challenger re-derives the *forged* root, has nothing to disagree with, and posts no counter-claim
— step 2 stops being an assumption and becomes expected behaviour, at which point this exact chain runs on
mainnet. The reachable ceiling is then the whole shared lockbox, measured here at 199,815 ETH, against a
0.08 ETH cost.

That is the value of this record: it fixes the L1 ceiling empirically, on production bytecode, so the
severity of FIND-001/FIND-002 no longer rests on an argument about what the portal would accept.

## Evidence

| ID | Artifact | Type |
|----|----------|------|
| `[EVD-045]` | `evidence/logs/l1-fullchain-run-1eth.txt` | executed run — full chain, 1 ETH received, 2/2 PASS |
| `[EVD-046]` | `evidence/logs/l1-fullchain-run-full-lockbox.txt` | executed run — lockbox drained to 0 |
| `[EVD-047]` | `evidence/poc/l1-fullchain-harness.sol` | the harness, cheatcode inventory verifiable in source |

## Remediation

None as a standalone L1 change: the portal deliberately does not re-derive L2 state, because adjudicating
the root is the dispute game's job, and re-deriving it on L1 would duplicate the proof system. The
actionable consequences are the ones FIND-001 and FIND-002 carry — the executor's acceptance check must be
sound, and the proof program must be able to disagree with the producer.

Two hardening items are visible independently of that:

- `ETHLockbox` has no per-chain accounting, so one chain's portal can withdraw the entire shared balance. A per-portal ledger would bound a single chain's failure to that chain's deposits.
- The creation bond is flat regardless of the value reachable through the claimed root (FIND-005). Value-scaled bonding would change the economics of asserting a root.

## Duplicate / disclosure status

Not an independent submission — the L1 behaviour is by design and would be closed as such. Its place is as
the executed evidence exhibit inside Immunefi #82416, replacing the `vm.store`-based harnesses. Coordinated
disclosure only; `audit-submission/` is prepared for external audit review, not publication.

## References

- [CWE-345](https://cwe.mitre.org/data/definitions/345.html)
- [MITRE ATT&CK T1565.001](https://attack.mitre.org/techniques/T1565/001/)
