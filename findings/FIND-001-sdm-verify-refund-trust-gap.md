---
id: FIND-001
phase: exploit
status: final
tier: CONFIRMED
gate: [cwe_id, cvss_score, evidence, attck_id, remediation]
depends_on: []
produces: [report/technical-report.md]
---

# Finding: SDM post-exec Verify path adopts the producer-declared gas refund without recomputation

## Overview

| Field | Value |
|-------|-------|
| **CWE** | CWE-345 — Insufficient Verification of Data Authenticity |
| **CVSS** | 8.6 (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:C/C:N/I:H/A:N) |
| **Severity (demonstrated)** | High — forged refund accepted, canonical state root diverges from execution, fee revenue diverted; devnet run carried the forged root through to an L1 payout |
| **Severity (inherent)** | Critical — an L2 state root that is not a function of execution finalizes on L1 through the standard withdrawal path |
| **Feasibility** | true — the acceptance path is exercised by the prior-session devnet run `[EVD-009]`, `[EVD-010]`, and every cited line was re-read in this checkout |
| **Confidence tier** | `[CONFIRMED]` for the code defect and for the devnet acceptance chain; the mainnet-scale payout ceiling stays `[POSSIBLE]` (see FIND-005) |
| **ATT&CK ID** | T1565.001 |
| **ATT&CK Name** | Data Manipulation: Stored Data Manipulation |
| **Target** | OP Stack L2 consensus execution (SDM / post-exec gas metering) |
| **Component** | `rust/alloy-op-evm` `OpBlockExecutor`, reached from `rust/op-reth/crates/evm` and `rust/kona/crates/proof/executor` |
| **Version** | This checkout of `ethereum-optimism/optimism` (working copy is **not a git repository**, so no commit can be pinned from it — pin from a fresh clone before submission) |

## Description

The SDM post-exec mechanism lets a block carry an `SDMGasEntry` list declaring a per-transaction gas
refund. The executor handles the two directions asymmetrically.

**Produce mode** arms the inspector and derives the refund from execution
(`rust/alloy-op-evm/src/block/mod.rs:953-980`, `[EVD-002]`):

```rust
if self.post_exec.is_producing() {
    self.evm.begin_post_exec_tx(PostExecTxContext { tx_index, kind: ... });
}
...
let (post_exec_refund, warming_events) = if self.post_exec.is_producing() {
    let PostExecExecutedTx { refund_total: refund, refund_events } =
        self.evm.take_last_post_exec_tx_result();
```

**Verify mode** never arms the inspector and takes the declared value instead
(`mod.rs:981-986`, `[EVD-002]`):

```rust
} else {
    (
        self.verifier_post_exec_refund_for_tx(tx_index, is_deposit, false, evm_gas_used)?,
        Vec::new(),
    )
};
```

`verifier_post_exec_refund_for_tx` (`mod.rs:534-567`, `[EVD-001]`) applies exactly one numeric
constraint to that value — a magnitude bound, not an equality against a recomputation:

```rust
let Some(refund) = self.post_exec.verifier_refund(tx_index) else {
    return Ok(0);
};
...
if refund > evm_gas_used {
    return Err(Self::invalid_post_exec_payload(format!(
        "payload refund {refund} exceeds evm_gas_used {evm_gas_used} for tx index {tx_index}"
    )));
}
Ok(refund)
```

The accepted number is then load-bearing for consensus state. It sets canonical gas
(`mod.rs:987`, `[EVD-002]`):

```rust
let canonical_gas_used = evm_gas_used.saturating_sub(post_exec_refund);
```

and it moves balances before commit (`mod.rs:726-754`, `[EVD-003]`) — the sender is credited while
the block beneficiary, `BASE_FEE_RECIPIENT` and `OPERATOR_FEE_RECIPIENT` are debited:

```rust
Self::add_state_balance(self.evm.db_mut(), state, sender, deltas.sender_balance_delta)?;
Self::sub_state_balance(self.evm.db_mut(), state, beneficiary, deltas.beneficiary_balance_delta)?;
Self::sub_state_balance(self.evm.db_mut(), state, BASE_FEE_RECIPIENT, deltas.base_fee_balance_delta)?;
Self::sub_state_balance(self.evm.db_mut(), state, OPERATOR_FEE_RECIPIENT, deltas.operator_fee_balance_delta)?;
```

Verify mode is entered whenever a post-exec payload transaction is present — `op-reth`
(`crates/evm/src/lib.rs:157-161`, `[EVD-004]`) and `kona`'s proof executor
(`crates/proof/executor/src/builder/core.rs:303-310`, `[EVD-005]`) both select
`PostExecMode::Verify(payload)` with no accompanying recomputation step. The consequence for the
dispute system is filed separately as FIND-002.

### The magnitude-only rule is the encoded specification, not an untested corner

The in-tree test suite pins this behaviour rather than merely leaving it unexercised (`[EVD-025]`).
`tests.rs:1449-1470` asserts that a **full refund of all gas consumed** is acceptable:

```rust
// Boundary: refund == evm_gas_used is permitted (canonical_gas_used ends up at zero).
let ok = executor
    .verifier_post_exec_refund_for_tx(2, false, false, 50_000)
    .expect("refund equal to evm_gas_used is permitted");
assert_eq!(ok, 50_000);
```

`test_post_exec_producer_verifier_roundtrip` (`:1259-1306`) feeds the verifier the entries the producer
just produced, so the suite never supplies a within-bound value that differs from the recomputed one.
Across the whole verify-path inventory — `test_verifier_rejects_malicious_payload_whose_refunds_hide_pre_refund_overuse`,
`test_verifier_accepts_payload_when_pre_refund_stays_below_limit`,
`test_verifier_rejects_payload_targeting_non_normal_tx`, `test_verifier_rejects_refund_exceeding_evm_gas`,
`test_verifier_returns_zero_when_no_entry_for_tx`, and the roundtrip — **none** asserts equality against a
locally recomputed refund.

Two consequences. The "nobody considered the verify path" reading is unavailable: the path was considered,
tested, and bounded — just not derived. And a fix is a deliberate specification change rather than a bug
patch, because the boundary assertion above must be revisited when an equality check lands, or it will
fail an existing test.

### Every adjacent integrity property *is* enforced — the missing recompute is the only gap

`PostExecState` (`mod.rs:113-243`) closes seven structural avenues around this guard (`[EVD-037]`):

| # | Property | Lines |
|---|----------|-------|
| 1 | A zero-refund entry invalidates the payload — no padding entries | 123-129 |
| 2 | A duplicate `tx_index` invalidates the payload — no two entries for one tx | 130-136 |
| 3 | An entry is consumed exactly once (`remaining.remove`) — no replay of a single entry | 199-203 |
| 4 | The payload is bound to the block number | 159-169 |
| 5 | The in-block `0x7D` payload must **equal** the payload the mode was constructed from, and a second `0x7D` tx is rejected | 205-226 |
| 6 | Entries left unconsumed at `finish()` are detected | 228-233 |
| 7 | A `Verify` block that claims a payload but never carries the `0x7D` tx is detected — with an in-line comment explaining why the unconsumed-entries check alone would miss it | 235-242 |

This changes how the finding should be argued. Padding, duplicate entries, entry replay, block-number
mismatch, payload substitution, a duplicated or omitted `0x7D` transaction, and orphaned entries are all
rejected. Whoever wrote this reasoned carefully about payload integrity. **The single absent check is
equality against a locally recomputed value** — which, together with the test suite pinning the magnitude
bound as the intended rule, points to a deliberate design decision rather than an oversight.

It also settles a scoping question: there is **no second exploitable defect** in this mechanism. Every
structural avenue adjacent to the guard was examined and is closed. The report rests on one defect, not a
cluster.

## Affected Component

- **Endpoint/File:** `rust/alloy-op-evm/src/block/mod.rs:534-567` (guard), `:953-997` (mode split), `:663-755` (balance settlement)
- **Parameter:** `SDMGasEntry.gas_refund` inside the block's post-exec (`0x7D`) transaction payload
- **Authentication required:** Yes — the block must be accepted from the sequencer, and `op-node`'s `isValidBatchTx()` verifies the batcher signature
- **Privilege required:** High — control, compromise, or collusion of the sequencer/batcher signing key

## Exploitation Path

### Prerequisites

- [x] The Lagoon fork is active on the target chain — `is_sdm_active_at_timestamp()` is `is_lagoon_active_at_timestamp()` (`op-reth/crates/evm/src/lib.rs:144-146`, `[EVD-004]`)
- [ ] **Not satisfied on any registered chain today**: `lagoon_time` is absent from all 21 hardfork-config nodes in the in-repo superchain registry (`[EVD-007]`)
- [x] Block production under attacker control (sequencer key), so the forged payload reaches validators with a valid batch signature
- [x] A validator or proof program running the Verify path — both do (`[EVD-004]`, `[EVD-005]`)

### Steps

1. Produce an L2 block containing a normal user transaction plus the post-exec (`0x7D`) transaction.
2. Set that transaction's `SDMGasEntry.gas_refund` to a value larger than the refund execution actually earns, keeping it `<= evm_gas_used` so the single guard at `mod.rs:560` passes.
3. Submit the block through the engine API. Verify-mode validators adopt the declared refund, subtract it from `canonical_gas_used`, credit the sender and debit the fee recipients, and accept the resulting state root — `engine_newPayload` returns `VALID` (`[EVD-009]` §3 phase 1, L2 block 57227).
4. The honest-execution state root and the accepted state root differ (`[EVD-009]`: baseline block 176, honest `0x3bfa76e6…` vs on-chain `0x0a5e8ca6…`).
5. Withdraw normally from the forged state: `L2ToL1MessagePasser.initiateWithdrawal`, then the standard L1 sequence — `DisputeGameFactory.create` → `resolve` → `proveWithdrawalTransaction` → `finalizeWithdrawalTransaction`. No stage on that path re-derives L2 state (FIND-004).

### Payload

```jsonc
// conceptual shape of the forged post-exec payload entry
{
  "tx_index": 1,
  "gas_refund": "<any value <= evm_gas_used of tx 1>"   // only bound checked: mod.rs:560
}
```

## Evidence

All artifacts are hashed in `.engage/evidence/evidence.json` and re-verify with
`evidence_kit.py verify` (17/17 VERIFIED at the time of writing).

| ID | Artifact | Type |
|----|----------|------|
| `[EVD-001]` | `evidence/code/verifier-refund.txt` | source quote — the magnitude-only guard |
| `[EVD-002]` | `evidence/code/produce-verify-asymmetry.txt` | source quote — Produce vs Verify split, `canonical_gas_used` |
| `[EVD-003]` | `evidence/code/settlement-deltas.txt` | source quote — balance deltas applied from the declared value |
| `[EVD-004]` | `evidence/code/post-exec-mode-selection.txt` | source quote — Verify selection and the Lagoon gate |
| `[EVD-007]` | `evidence/code/fork-activation.txt` | derived analysis — 21 `karst_time` nodes, 0 `lagoon_time` |
| `[EVD-009]` | `evidence/poc/addendum-82416-e2e.md` | prior-session devnet run record (2026-08-03) |
| `[EVD-010]` | `evidence/poc/devnet-e2e-withdrawal.txt` | prior-session tool output |
| `[EVD-014]` | `evidence/poc/proposed-fix.patch` | proposed fix |

- **Timestamp:** 2026-08-03 (static re-verification against this checkout); devnet run recorded 2026-08-03 in a prior session
- **Provenance caveat:** the devnet execution was **not re-run inside this engagement**. What this engagement re-established is that every quoted line still reads as cited in the current tree.

## Impact

A value that any validator can derive locally is instead accepted as declared. Two consequences,
different in kind:

1. **Fee-revenue diversion.** Value moves from the fee recipients and the block beneficiary to the transaction sender, bounded by `refund <= evm_gas_used`.
2. **State-root divergence.** The canonical L2 state root stops being a function of execution. Because the withdrawal path performs no independent re-derivation of L2 state (`[EVD-009]` stage table, `[EVD-008a]`, `[EVD-008b]`), an accepted forged root flows to L1 finalization. In the devnet run this produced a real 0.5 ETH transfer on L1 at block 57333 — funded by a deposit made in that same session, so third-party net loss there was zero.

## Remediation

### Short-term

Recompute the refund in Verify mode and reject the block on mismatch, replacing the magnitude bound
with an equality check against the locally derived value. `[EVD-014]` contains a proposed patch.

### Long-term

Treat every producer-declared, state-relevant field as unverified input by construction: arm the
inspector in Verify mode as well, so both directions derive the same quantity from the same code, and
keep the magnitude bound only as a cheap pre-filter.

### There is no interim flag-based mitigation — the fix has to be the recompute

Established from the activation plumbing (`[EVD-043]`):

- **Production is opt-in and off by default.** A sequencer enables SDM payload production through the `admin_setOperatorSdmOptIn` admin RPC, and the harness notes "SDM is disabled by default on every process boot". That is not a mitigation against a malicious sequencer — the attacker flips its own opt-in. It only prevents accidental production.
- **Acceptance has no per-node switch.** `op-reth` decides via `is_sdm_active_at_timestamp` (the chain spec) with no operator override; the only `sdm_active_override` in the tree lives inside the **kona proof executor** and falls back to `self.config.is_sdm_active(timestamp)`. The comment in the acceptance harness states it plainly: *"Verifier nodes do not need to"* opt in.
- **A per-node acceptance override would be unsafe anyway.** Nodes disagreeing about whether to accept a post-exec transaction would diverge on the state root. So a flag is not an available emergency lever even in principle.

Consequence: between a `lagoon_time` activation and the recompute landing, there is **no operator-side lever at all**. The guardian levers in `[EVD-009]` §5 act on withdrawal finalization, not on acceptance, and FIND-006 shows they do not cover the interop consumer either. This is why item 1 of the remediation is not optional and why it must land before activation rather than alongside it.

### Validation

The comparison logic already exists in-tree as `compare_refunds` in
`op-reth/crates/post-exec-replay/src/replay.rs:254-300` (`[EVD-006]`, FIND-003), including a
`PayloadRefundExceedsRawGas` mismatch kind and unit tests. Wire it into the Verify path and assert
that a block carrying a tampered `SDMGasEntry` is rejected by both `op-reth` and the `kona` proof
program.

## Duplicate / disclosure status

This is the same defect class as **Immunefi submission #82416** filed by this operator
(`[EVD-011]`, `[EVD-009]`). It must be attached to that submission as an addendum, not filed as a
new report. No public disclosure until the program authorizes it.

## References

- [CWE-345](https://cwe.mitre.org/data/definitions/345.html)
- [MITRE ATT&CK T1565.001](https://attack.mitre.org/techniques/T1565/001/)
- `rust/UPDATING-RETH.md` — in-tree fork maintenance context
- `op-acceptance-tests/tests/sdm/` — existing SDM acceptance harness, the natural home for a regression test
