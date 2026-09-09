---
id: FIND-008
phase: exploit
status: final
tier: INFO
gate: [cwe_id, evidence, attck_id]
depends_on: []
produces: [report/technical-report.md]
---

# Finding: Zero-address recipient is rejected by setWithdrawalRoute but accepted by setRecipient and initialize

## Overview

| Field | Value |
|-------|-------|
| **CWE** | CWE-20 — Improper Input Validation |
| **CVSS** | — (informational) |
| **Severity** | Informational — inconsistent validation across sibling writers of the same value |
| **Tier** | `[INFO]` |
| **Feasibility** | `null` — reachable only by the ProxyAdmin owner, a role the design fully trusts |
| **ATT&CK ID** | T1565.001 |
| **ATT&CK Name** | Data Manipulation: Stored Data Manipulation |
| **Component** | `packages/contracts-bedrock/src/L2/FeeVault.sol` and its four subclasses |
| **Version** | This checkout (Solidity 0.8.25) |

## Description

`FeeVault.recipient` has three writers. Only one validates it (`[EVD-035]`):

| Writer | Line | Zero-address guard |
|--------|------|--------------------|
| `initialize(address _recipient, …)` | 84-96 | **none** |
| `setRecipient(address _newRecipient)` | 115-122 | **none** |
| `setWithdrawalRoute(address _newRecipient, …)` | 142-154 | `require(_newRecipient != address(0), "FeeVault: zero recipient")` |

The guarded function's own documentation acknowledges the hazard of the split path:

```solidity
/// @notice Updates the recipient and network to which vault fees will be withdrawn.
///         This function is safer than calling `setRecipient` and `setWithdrawalNetwork` separately,
///         and should be preferred if both are being updated.
```

so the inconsistency is visible in the source but resolved only by convention.

A zero recipient does not revert on withdrawal — it silently destroys the funds. `withdraw()` routes
through `SafeCall.send`, which is a raw `call`:

```solidity
success_ := call(_gas, _target, _value, 0, 0, 0, 0)
```

`call` to `address(0)` succeeds, so `require(success, "FeeVault: failed to send ETH to L2 fee recipient")`
passes and the ETH is gone. On the `WithdrawalNetwork.L1` branch the same address becomes the L1 withdrawal
target, with the same outcome once finalized.

Two properties make the state sticky. `withdraw()` is permissionless, so anyone can trigger the transfer
once the balance clears `minWithdrawalAmount` — the operator does not get a chance to notice first. And the
`L2ContractsManager` upgrade path replays the stored configuration back through `initialize`
(`L2ContractsManagerUtils.readFeeVaultConfig` → `IFeeVault.initialize`), so a zeroed recipient is preserved
across upgrades rather than reset by one.

## Why this is informational

Every writer is gated on `_assertOnlyProxyAdminOwner()` (or `_assertOnlyProxyAdminOrProxyAdminOwner()` for
`initialize`). That is the role the design already trusts completely, and the scope notes for this
engagement record that findings requiring such a role are excluded by program convention unless the trust
boundary itself is broken. It is not broken here.

What is worth recording is the **inconsistency**: the same value, three writers, one guard, and an
irreversible consequence. That is a configuration-error class rather than an attack, and it is a one-line
fix in each of the two unguarded writers.

## Affected Component

- **File:** `src/L2/FeeVault.sol:84-96` (`initialize`), `:115-122` (`setRecipient`), `:158-182` (`withdraw`)
- **Parameter:** `recipient`
- **Authentication required:** Yes — ProxyAdmin owner
- **Privilege required:** High

## Evidence

| ID | Artifact | Type |
|----|----------|------|
| `[EVD-035]` | `evidence/code/l2-feevault-drain-review.txt` | source quotes — the three writers, the single guard, `SafeCall.send`, and the subclass inventory |

## Impact

No unauthorized impact. If the recipient is ever set to the zero address — by a scripting error, a
mis-ordered upgrade, or a bad parameter in a governance action — all subsequent fee revenue from that vault
is permanently destroyed, the destruction can be triggered by any caller, and an upgrade will not clear it.
Given that these four vaults collect the chain's entire fee revenue, the cost of the mistake is bounded only
by how long it goes unnoticed.

## Remediation

### Short-term

Add the guard already present in `setWithdrawalRoute` to the other two writers:

```solidity
function setRecipient(address _newRecipient) external {
    _assertOnlyProxyAdminOwner();
    require(_newRecipient != address(0), "FeeVault: zero recipient");
    ...
}
```

and the equivalent line in `initialize`. If a zero recipient must remain expressible for some deployment
flow, invert the treatment instead: make `withdraw()` revert while `recipient == address(0)`, which fails
safe rather than burning.

### Long-term

Where a value is written by more than one entry point, validate it in a shared internal setter so the guard
cannot be applied to a subset. The pattern here — a combined setter documented as "safer than" its
components — is a signal that the components need the same checks, not that callers should be trusted to
prefer the combined one.

### Validation

A unit test asserting that `setRecipient(address(0))` and `initialize(address(0), …)` both revert, and — if
the fail-safe variant is chosen instead — that `withdraw()` reverts while the recipient is zero.

## Duplicate / disclosure status

Unrelated to Immunefi #82416. A low-priority hardening note, not a severity claim, and likely
non-qualifying on its own given the trusted-role precondition. Coordinated disclosure only.

## References

- [CWE-20](https://cwe.mitre.org/data/definitions/20.html)
- [MITRE ATT&CK T1565.001](https://attack.mitre.org/techniques/T1565/001/)
