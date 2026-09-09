---
id: FIND-010
phase: exploit
status: final
tier: CONFIRMED
gate: [cwe_id, evidence, attck_id, remediation]
depends_on: [exploit/findings/FIND-009-l1-fullchain-fabricated-root-to-lockbox-drain.md]
produces: [report/technical-report.md]
---

# Finding: the Guardian's blacklist cannot unwind a poisoned anchor — `setAnchorState` is permissionless and `getAnchorRoot` never re-checks the stored game

## Overview

| Field | Value |
|-------|-------|
| **CWE** | CWE-284 — Improper Access Control (authority gap between the containment lever and the state it is meant to contain) |
| **Severity (demonstrated)** | Informational–Low — the authority gap is quoted from source; no poisoning was executed |
| **Severity (inherent)** | High — the Guardian's kill switch stops payouts but cannot restore the anchor; recovery escalates to a ProxyAdmin-owner reinitialization with a constraint the attacker chooses |
| **Tier** | `[CONFIRMED]` for the access-control gap and the missing re-check; `[POSSIBLE]` for reaching it, because the precondition is FIND-009's (a valid game over a fabricated root) |
| **Feasibility** | `null` — not executed. `setAnchorState` itself is a public function with no privilege requirement; the gate is obtaining a game that passes `isGameClaimValid` |
| **ATT&CK ID** | T1565.001 — Data Manipulation: Stored Data Manipulation |
| **Component** | `packages/contracts-bedrock/src/dispute/AnchorStateRegistry.sol` |
| **Version** | This checkout (`D:\optimism-develop`) |

## Description

The engagement corpus records the Guardian levers as the containment answer to an accepted forged root
(`[EVD-009]` §5, cited from FIND-004): `SuperchainConfig.pause`, `AnchorStateRegistry.pause`,
`blacklistDisputeGame`, `updateRetirementTimestamp`, `setRespectedGameType`. A reviewer put the same list
back to the operator on 2026-08-04 as the reason the withdrawal hurdle is not one-time. That is correct
**for finalization**. It is not correct for the anchor.

Three quoted facts, all from `AnchorStateRegistry.sol` in this checkout:

**1. `setAnchorState` is `public` and carries no Guardian assertion (`:346-361`).** Every other mutator in
the file opens with `_assertOnlyGuardian()`; this one does not:

```solidity
function setAnchorState(IDisputeGame _game) public {
    if (!isGameClaimValid(_game)) {
        revert AnchorStateRegistry_InvalidAnchorGame();
    }
    (, uint256 anchorL2BlockNumber) = getAnchorRoot();
    if (_game.l2SequenceNumber() <= anchorL2BlockNumber) {
        revert AnchorStateRegistry_InvalidAnchorGame();
    }
    anchorGame = _game;
    emit AnchorUpdated(_game);
}
```

Anyone may call it. `FaultDisputeGame.sol:1062`, `SuperFaultDisputeGame.sol:1022` and
`ZKDisputeGame.sol:731` also call it opportunistically inside `try … catch { }`, so the promotion happens
as a side effect of ordinary resolution as well.

**2. `getAnchorRoot()` reads the stored game unconditionally (`:194-202`).** No blacklist check, no
retirement check, no pause check, no status check:

```solidity
function getAnchorRoot() public view returns (Hash, uint256) {
    if (address(anchorGame) == address(0)) {
        return (startingAnchorRoot.root, startingAnchorRoot.l2SequenceNumber);
    }
    return (Hash.wrap(anchorGame.rootClaim().raw()), anchorGame.l2SequenceNumber());
}
```

Contrast `isGameProper` (`:275-297`), which *does* consult `isGameBlacklisted`, `isGameRetired` and
`paused()`. Those checks guard `isGameClaimValid` — the finalization path and the promotion precondition —
and are re-read on every `finalize`. They are not on the read path for the anchor that has already been
promoted.

**3. No Guardian function clears `anchorGame`.** The identifier is written in exactly two places
(`grep -n anchorGame` → `:110-115`, `:359`). `blacklistDisputeGame` writes
`disputeGameBlacklist[_disputeGame] = true` and nothing else; there is no `clearAnchorGame`, no
`setAnchorGame`, no reset. The only other writer is `initialize` (`:110-115`), which is
`reinitializer(initVersion())` behind `_assertOnlyProxyAdminOrProxyAdminOwner()`.

### The consequence, stated as a sequence

1. An attacker obtains a game over a fabricated root that reaches `DEFENDER_WINS` and finalization — this is exactly the state FIND-009 executed end to end on a mainnet fork (addendum 010, `ETHLockbox` −1,000 ETH, all legs `status 1`, no cheatcodes).
2. While that game is still `isGameClaimValid`, `setAnchorState(game)` is called — by the attacker, or automatically by the game's own resolution path. `anchorGame` now points at it.
3. The Guardian notices and calls `blacklistDisputeGame(game)`. This works as documented: `isGameProper` → false, so `isGameClaimValid` → false, and **no further withdrawal can finalize against that game**.
4. `getAnchorRoot()` continues to return the fabricated root and its `l2SequenceNumber`, because it never asks whether `anchorGame` is blacklisted.
5. That value is load-bearing for every future game: `FaultDisputeGame.initialize` requires `l2BlockNumber() > anchor.l2SequenceNumber`, and a game with no parent takes the anchor as its starting root.

So the blacklist is a payout brake, not a rollback. The Guardian can stop the theft and still be left with
a registry that reports a root nobody derived.

### The recovery path has a constraint the attacker picks

`initialize` is the only way to clear it, and clearing is conditional (`:106-116`):

```solidity
if (rootChanged && address(anchorGame) != address(0)) {
    (, uint256 currentSeqNum) = getAnchorRoot();
    if (_startingAnchorRoot.l2SequenceNumber <= currentSeqNum) {
        revert AnchorStateRegistry_InvalidAnchorGame();
    }
    anchorGame = IDisputeGame(address(0));
}
```

The replacement anchor must be **strictly ahead** of the poisoned one. Since step 2's
`l2SequenceNumber` is chosen by the attacker and only has to exceed the then-current anchor, a poisoning
transaction that names an absurdly high sequence number forces the recovery to name a higher one — i.e.
the honest operator must reinitialize with a starting anchor beyond a block the chain has not produced, or
migrate the proxy. The PoC sets `l2BlockNumber = 99999 * 365 * 24 * 3600 / 2 = 1,576,784,232,000`,
approximately **99,999 years** of L2 block production at 2 s/block, so the recovery must name a block
number beyond that. This is a recovery-cost amplification, and it is available at the same 0.08 ETH bond as
the rest of the path.

## Affected Component

- **File:** `src/dispute/AnchorStateRegistry.sol:346-361` (`setAnchorState`), `:194-202` (`getAnchorRoot`), `:174-181` (`blacklistDisputeGame`), `:106-116` (the only clear path), `:275-297` (`isGameProper`, for contrast)
- **Parameter:** `anchorGame`
- **Authentication required:** No — `setAnchorState` is `public`
- **Privilege required:** None for the call itself; the precondition is a game passing `isGameClaimValid`

## Evidence

| ID | Artifact | Type |
|----|----------|------|
| — | direct quotes above, read from `D:\optimism-develop\packages\contracts-bedrock\src\dispute\AnchorStateRegistry.sol` on 2026-08-04 | source quote |
| addendum 010 | `exploit/phase4-addendum-010-cheatcode-free-l1-chain-run.md` | executed run producing the state that step 1 requires, cheatcode-free, hash-sealed |
| `[EVD-009]` §5 | `evidence/poc/addendum-82416-e2e.md` | the Guardian lever list this finding bounds, including the 7,884,000 s pause auto-expiry |

**What is missing:** no poisoning was executed. `setAnchorState` was not called on any fork in this
engagement, and the recovery constraint was not exercised. That is why the reach is `[POSSIBLE]` even
though the authority gap is `[CONFIRMED]`.

## Impact

The Guardian is the documented answer to "what if an invalid root is accepted", and this bounds that
answer precisely:

- **Covered:** payouts. `blacklistDisputeGame` / `updateRetirementTimestamp` / `pause` are re-read on every `finalize` through `isGameProper`, so a proven-but-unfinalized exit can be retroactively killed. The reviewer's point on 2026-08-04 is correct on this axis.
- **Not covered:** the anchor. Promotion is permissionless, the read path never re-validates, no Guardian function reverses it, and the only reversal is a ProxyAdmin-owner reinitialization whose admissible parameter range the attacker constrains.
- **Compounding:** the Guardian pause auto-expires after 7,884,000 s and re-pausing requires an `unpause` first (`[EVD-009]` §5). Time pressure sits on the defender, and the poisoned anchor does not expire.

No fund loss is claimed here beyond FIND-009's. What this finding claims is that the *containment story*
has a hole, which matters because that story is the reason the withdrawal path's severity was argued down.

## Remediation

### Short-term

Make the anchor read fail closed. One line, at the point of use:

```solidity
function getAnchorRoot() public view returns (Hash, uint256) {
    if (address(anchorGame) == address(0) || !isGameProper(anchorGame)) {
        return (startingAnchorRoot.root, startingAnchorRoot.l2SequenceNumber);
    }
    return (Hash.wrap(anchorGame.rootClaim().raw()), anchorGame.l2SequenceNumber());
}
```

so that blacklisting or retiring a game demotes it as an anchor by the same act, with no new privileged
function and no migration. Reverting instead of falling back is the more conservative variant and is worth
considering, since a silent fallback changes the sequence-number floor.

### Long-term

Two structural notes. First, `setAnchorState` being `public` is only safe while `isGameClaimValid` is
sound — it inherits the entire trust chain of the dispute system with no second factor, and it is the one
mutator in the file without a Guardian assertion. Adding a Guardian-settable override (`clearAnchorGame`,
or a direct `setAnchorGame`) gives the containment lever the same reach as the promotion path. Second,
wherever a containment lever exists, the state it is supposed to contain should be enumerated and tested:
the gap here is not a missing check in isolation, it is that "blacklist stops the game" was assumed to
mean "blacklist stops everything downstream of the game".

### Validation

Three tests. (a) Promote a game to `anchorGame`, blacklist it, and assert `getAnchorRoot()` no longer
returns its root. (b) Assert `setAnchorState` from an arbitrary EOA either reverts or is intentionally
permitted, so the intent is pinned either way. (c) Poison with a large `l2SequenceNumber` and assert a
recovery path exists that does not require naming a higher one.

## Duplicate / disclosure status

Related to but distinct from Immunefi #82416: that submission is about acceptance of a forged root, this is
about the recovery authority afterwards. It is also the item the 2026-08-04 reviewer exchange conceded
independently ("`setAnchorState` is indeed unauthenticated"; "`getAnchorRoot()` does not re-check the
blacklist for an already-set anchor, so unwinding a poisoned anchor requires the ProxyAdmin-owner
reinitialization path rather than a Guardian call"). Since both parties reached it separately, it is the
cheapest item in the corpus to agree on. Coordinated disclosure only.

## References

- [CWE-284](https://cwe.mitre.org/data/definitions/284.html)
- [MITRE ATT&CK T1565.001](https://attack.mitre.org/techniques/T1565/001/)
- `FaultDisputeGame.sol:1062`, `SuperFaultDisputeGame.sol:1022`, `ZKDisputeGame.sol:731` — the `try … catch` promotion call sites
