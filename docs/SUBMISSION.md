# SDM Post-Exec Refund → ETHLockbox：全体チェーン提出資料

作成 2026-07-26 / 提出先：監査法人
報告者：Yomibito Shirazu (Yohei Ishijima)
対象：`ethereum-optimism/optimism`
一次資料：`docs/reports/VULNERABILITY_REPORT.md`（開示レポート、2026-07-23）

---

## 0. 本資料の位置づけ

Immunefi #82416（2026-06-19 提出、同日 Closed）は executor レベルの
「Verify 経路が refund を再計算しない」ことを静的解析と 15 テストで示した。
閉鎖理由は、critical 主張の 3 点を `[NOT PROVEN]` と自ら明記していたためである。

- dispute game が偽造 output root を受理すること
- 正直な challenger が拒否できないこと
- op-geth parity

本資料は #82416 を**第1段**として引き継ぎ、refund の偽造から L1 着金までの
経路を、どこまでが実行済みでどこからが未実行かを行単位で分けて提示する。

2026-07-26、`lagoon_time = 0` の devnet 上で **refund の偽造そのものが実行され、
canonical block として受理された**（§3-8）。現時点の到達点は次のとおり。

| 対象 | 判定 |
|---|---|
| 正常 withdrawal pipeline（deposit → L2 → prove → finalize → 着金） | **Confirmed**（§3-7、devnet 実行） |
| Verify が refund を再計算しないこと | **Confirmed**（§3-1 実コード 33 テスト、§3-8 実チェーン） |
| 偽造 0x7D が canonical block として受理されること | **Confirmed**（§3-8、`newPayload: VALID`、receipt `gasUsed 0`） |
| L2 手数料収入を 100% 消滅させられること | **Confirmed**（§3-8、実測 525,000,052,500,000 wei → 0） |
| L1 の払い出し上限が lockbox 残高のみであること | **Confirmed**（§3-4、forge 5 テスト） |
| 偽造で残った残高が withdrawal に乗ること | **Confirmed（L2 側）**（§3-8(e)） |
| 同一チェーン上での L1 着金までの連結 | **未実行**（工程自体は §3-7 で Confirmed） |
| sender の開始資産を超える不正利益 | **不成立**（§3-8(d)、上限 `refund <= evm_gas_used`） |
| 第三者元本の純窃取 | **不成立**（§3-8(d)、借方貸方が一致） |

**本件は第三者の元本を奪う脆弱性ではない。** sequencer が自らの主張だけで
L2 手数料収入を任意にゼロにでき、fault proof がその主張を同じ主張と
突き合わせるため検出されない、という権限設計と検証設計の欠陥である。
未証明・未確認の項目を証明済みとして扱わず、成立しないと判明した主張は
**不成立**と明記することが、本資料の設計方針である。

---

## 1. 主張

`PostExecMode::Verify` は sequencer が payload に載せた `gas_refund` を
**再計算せずに受理**する。唯一の制約は `refund <= evm_gas_used` のサイズキャップ
である。したがって、

1. sequencer は自分が署名した tx に `refund = evm_gas_used` を設定できる
2. 決済は手数料金庫 3 者から引き、`tx.signer()`（= sequencer）に加算する
3. fault proof の再実行は**同じ payload の refund を入力に使う**ため、
   challenger は同一の root を再導出する。両者は必ず一致する
4. dispute game は `counteredBy == address(0)` により内容不問で
   `DEFENDER_WINS` に解決する
5. 加算された L2 残高は通常の withdrawal で共有 L1 lockbox から出金される

3 が本件の核心である。検証が producer の主張を producer 自身の主張と
突き合わせるため、**検査が循環している**。refund は再計算による事実ではなく
仮定による事実として扱われる。

---

## 2. 証拠の分類

| 記号 | 意味 |
|---|---|
| **[RAN]** | 実コードに対してテストを実行し、出力を得た |
| **[READ]** | 実ファイルを読み、file:line で引用した |
| **[MODEL]** | 実コードの条件を移植した Python モデルで再現した |
| **[未実行]** | まだ実行していない |

**[MODEL]** は実チェーンに接続しない。RPC も鍵も含まない。実コードのどの行を
移植したかを各条件のコメントに記載している。

---

## 3. 実行済みの証拠

### 3-1. Verify が refund を再計算しない **[READ] [RAN]**

`rust/alloy-op-evm/src/block/mod.rs`（branch `develop`, `0f0aba355d`）

| 行 | 内容 |
|---|---|
| `534-567` | `verifier_post_exec_refund_for_tx`。`544` で payload から読み、`560-564` で `refund > evm_gas_used` のみ検査、`566` で `Ok(refund)`。再計算は存在しない |
| `549-559` | payload が deposit / post-exec tx を指すとブロック無効。攻撃に使えるのは通常 tx のみ |
| `669-725` | `post_exec_settlement_deltas`。`712-714` で `sender_balance_delta = refund × effective_gas_price + operator_fee_delta` |
| `726-753` | `apply_post_exec_refund_to_state`。`add_state_balance(sender)` 1 回、`sub_state_balance` を beneficiary / `BASE_FEE_RECIPIENT` / `OPERATOR_FEE_RECIPIENT` に 3 回 |
| `628-646` | `sub_state_balance` は `checked_sub`。残高不足ならブロック拒否。refund の正当性は検査しない |
| `570-580` | `canonicalize_result_gas` が receipt の `gas_used` も減算する（可観測な痕跡） |

**実行**（`a7ab3fd3c4` + `patches/sdm-refund-trust-gap.patch`）

```
cargo test -p alloy-op-evm --lib block::tests::sdm
→ 33 passed; 0 failed
```

含まれるテスト：`test_verify_accepts_inflated_refund_without_recompute`、
`test_sdm_poc2_inflated_refund_drains_fee_vault_min` / `_max`、
`test_sdm_poc2_challenger_pre_fix_accepts_forged_refund_and_drains_vault`、
`test_sdm_poc2_strict_verify_rejects_inflated_refund`、
`test_post_exec_settlement_conserves_total_eth_supply`。

**実測値**（`test_sdm_poc2_wallet_drain_demo`）

```
Honest refund (gas):      2000
Max extra refund (gas):   21105
Applied extra refund:     1 gas
Operator fee vault drained: 500 wei
Attacker wallet gained:   500 wei
```

再現手順：`scripts/build-sdm-repro.sh` が基準コミットを固定して組み立てる。
パッチは現 `develop` には適用できない。基準は payload 内の blob hash
（`index 45e650b6b3`）から特定した `a7ab3fd3c4`（PR #21502, 2026-06-23）。

### 3-2. 金庫の払い出し先制約を迂回する **[READ] [MODEL]**

`packages/contracts-bedrock/src/L2/FeeVault.sol:139-163` の `withdraw()` は
`recipient` をストレージから読む。`msg.sender` は `Withdrawal` イベントに
記録されるだけで宛先に影響しない。`recipient` の変更は `setRecipient`（`115`）で
ProxyAdmin owner 権限を要する。

SDM の決済は `withdraw()` を経由しないため、以下がすべて適用されない。

- 権限チェック
- 宛先の固定
- `minWithdrawalAmount` の下限
- `Withdrawal` イベントの記録

```
python3 test_authority_bypass.py
→ 6 passed
```

- `withdraw()` を sequencer が呼んでも取得額は 0（`recipient` に届く）
- `setRecipient` は sequencer では revert
- SDM 経路は 500 wei を `tx.signer()` へ移す
- 両経路とも ETH 総量は保存される（mint も burn もない）
- underflow が唯一のガード。金庫はちょうど 0 まで引ける

### 3-3. dispute game は root claim を見ずに解決する **[READ] [RAN] [MODEL]**

| ファイル | 行 | 内容 |
|---|---|---|
| `FaultDisputeGame.sol` | `717` | `status_ = claimData[0].counteredBy == address(0) ? DEFENDER_WINS : CHALLENGER_WINS`。**root claim は参照されない** |
| `PermissionedDisputeGame.sol` | `21-26` | `move` / `step` は `proposer()` または `challenger()` 以外 revert |
| `AnchorStateRegistry.sol` | `262-266` | コード自身のコメント：*The root claim of a proper game IS NOT guaranteed to be valid* |

```
python3 test_fraud.py
→ 9 passed
```

`TRUSTED L1: DEFENDER_WINS — honest challenger SLASHED`、
bisection は 3 ラウンドで偽造ステップに収束。

### 3-4. L1 の出金上限は lockbox 残高のみ **[RAN]**

`evidence/ETHLockboxDrainCeiling.t.sol`（`contracts-bedrock`, `a7ab3fd3c4`）

```
forge test --match-contract ETHLockbox_DrainCeiling_Test
→ 5 passed; 0 failed
```

| 測定 | 結果 |
|---|---|
| 残高ちょうどの引き出し | lockbox が**厳密に 0** になる |
| 残高 +1 wei | `ETHLockbox_InsufficientBalance` で revert、残高は無変化 |
| 連続呼び出し | per-call 上限もレート制限も**なし** |
| **1 ETH 拠出した portal** | **プール全額 101 ETH を引き出せた** |

上流の既存テストには境界の決定的検証がない
（fuzz は `[balance+1, max]`、成功ケースは残高を要求額に合わせる）。

### 3-5. 全体チェーンの通し **[MODEL]**

```
python3 test_withdrawal_chain.py
→ 8 passed
```

```
偽造 refund (refund = evm_gas_used)
  → operator 金庫 −8,050,000 wei / 署名者 +8,533,000 wei
  → initiateWithdrawal が L2 残高を焼却
  → counteredBy == address(0) で DEFENDER_WINS
  → 2 つの遅延が経過
  → lockbox 5,000,000,000 → 4,021,041,000
     L1 アドレスが 978,959,000 wei を受領
```

同時に測定した性質。

- **勝敗は遅延を短縮しない。** `checkWithdrawal` の 4 番目（`646`）は proof
  提出時刻から測り、game を参照しない
- **6 フィールドはハッシュで束縛。** `target` / `value` を変えると
  `withdrawalHash` が変わり `Unproven` で revert
- **第三者が finalize できる。** `finalizeWithdrawalTransactionExternalProof` は
  `public` で権限チェックがなく、他人の proof を指定できる。ただし資金は
  元の `tx.target` へ届き、実行者は何も得ない
- **拠出額を超えて共有プールに到達する**（1,000 拠出 → 10,000 全額）

### 3-6. devnet 上の output root 提案 **[RAN]**

192.168.2.103（Anvil L1 / op-geth L2 / op-node / op-batcher / op-proposer）

```
gameCount()   = 1
game          = 0x849C738f610aBF20430048f6293D844bA4689A58
gameType      = 1 (PERMISSIONED, respectedGameType と一致)
l2BlockNumber = 5050
status        = 0 (IN_PROGRESS)
```

到達までに解決した障害は `devnet/HANDOVER-linux.md` に記録した。
主因は 4 段の連鎖（batcher 停滞 → L1 停止 → finalized タグ 0 →
proposer が `finalized_l2` を使い genesis と判定）で、
`anvil_setIntervalMining` で解いた。

### 3-7. L2→L1 出金の全行程 **[RAN]**

192.168.2.103 の devnet 上で、出金開始から L1 着金まで実行した。
すべて `status = 0x1`。receipt は
`devnet/artifacts/withdrawal/receipt-<hash>.json` に保存。

| ステップ | tx | 結果 |
|---|---|---|
| L1 → L2 deposit が L2 の `initiateWithdrawal` を起動 | `0x83bb0adcfed2aa4241d4d4a47b3ad684819ea1ffc3cdcd43f118a6944126aec9` | status 0x1 |
| `proveWithdrawalTransaction` | `0x0fbe11317cc8eacd998e8880d10f9e7b414d2cfe4d7f5c0a56088c7d6e213e74` | status 0x1 |
| `finalizeWithdrawalTransaction` | `0x48d251b77e6cda0f1d5f3168731cc6c4519395bf3e00593e4966763ece3b024a` | status 0x1 |

**残高の実測**

```
0xb94441b6Fb20776f61c97070E163D13DCA055170 (L1)
    0  →  500,000,000,000,000,000 wei (0.5 ETH)

OptimismPortal2 (L1)
    11.0 ETH  →  10.5 ETH
```

**経路の詳細**

| 項目 | 実測値 |
|---|---|
| L2 出金開始ブロック | 7390 |
| `withdrawalHash` | `0x27e94e64947ee6db8eeb74f2020b66d58aa4ca30529b2afdc594b31765a03a5f` |
| `sentMessages` storage slot | `keccak256(abi.encode(withdrawalHash, 0))`、`eth_getProof` の value `0x1` |
| 使用したゲーム | index 9、`0x895c3825B85Ca2b804DcE0d85F00D7171221eA7e`、`l2BlockNumber = 7462` |
| ゲームの解決結果 | **`DEFENDER_WINS`（status 2）** |
| `counteredBy` | `address(0)`（誰も反論していない） |
| 遅延の経過 | proof 提出後 950,000 秒 → `resolve()` → 解決後 400,000 秒（`evm_increaseTime`） |

**資金の出所 — この実行は正常往復である**

| 項目 | 金額 | 出所 |
|---|---|---|
| L1 → L2 deposit（`msg.value`） | 0.5 ETH | anvil test account #1 が拠出 |
| L2 上で生成された残高 | 0.5 ETH | 上記 deposit の裏付けあり |
| withdraw した金額 | 0.5 ETH | 同一の 0.5 ETH |
| L1 target が受領 | 0.5 ETH | 同一の 0.5 ETH |
| **第三者資金からの純増** | **0** | — |

**したがって §3-7 が実証したのは「正常 withdrawal の control run」である。**
正規に deposit された裏付け済み残高が、通常の withdrawal 経路を端から端まで
通ったことを示す。SDM refund によって第三者資金を取得して withdraw できた
ことは示していない。

**この実行に含まれていない要素**

- SDM PostExec `0x7D` トランザクション
- sequencer-defined refund
- FeeVault から sender への settlement
- refund 由来の残高
- invalid あるいは異論のある root への challenge
- Kona による SDM re-execution

**`DEFENDER_WINS` の解釈**

`counteredBy == address(0)` だったのは、**この root が正常 deposit のみを含む
通常の root であり、反論すべき理由が誰にもなかったから**である。
偽造 root に対して正直な challenger が反論できなかったことを示すものではない。

`resolve()` / `resolveClaim()` に `onlyAuthorized` が付いていないこと
（`PermissionedDisputeGame.sol:21-26` の制限は `move` と `step` のみ）は
事実であり、実際に proposer でも challenger でもない anvil アカウントから
解決を発火させた。**ただしこれ自体は欠陥ではない。** 呼び出し者は解決結果を
選べず、ゲーム内で既に形成された状態を確定させるだけである。誰も最終処理を
呼ばずにゲームが停止することを防ぐ liveness 設計と解される。

正確な表現は次のとおり。

- 攻撃者は自分で**解決を発火**できる ← 事実
- 攻撃者は自分で `DEFENDER_WINS` を**選択**できる ← 誤り

**署名について**

秘密鍵素材を手動で扱わなかったが、署名は行われている。正確には
**anvil が保持する unlocked test account を RPC 経由で使用し、
anvil が代わりに署名・送信した**（`cast send --unlocked`）。
`--unlocked` は認証・署名の不存在を意味しない。
L2 側は `OptimismPortal2.depositTransaction` の `_data` に
`initiateWithdrawal` の calldata を載せることで L1 から駆動した。

---

### 3-8. SDM 有効な devnet 上での refund 偽造 **[RAN]**

2026-07-26、`lagoon_time = 0` の devnet（L1 chainId 31338 / L2 chainId 902、
EL は op-reth `--rollup.operator-sdm-opt-in true`）で実行。
op-reth 自身の申告：

```
admin_sdmStatus →
{"operatorSdmOptIn":true,"protocolActive":true,"effective":true,"activationTime":0}
```

Lagoon の起動には dependency set が必須（`op-node`: "the Lagoon upgrade is
scheduled (timestamp = 0) but not dependency set is configured"）。形式は
`rust/op-core/interop/depset/static_depset.go:52-55` の
`{"dependencies": {"<10進 chainID>": {}}}`。

**(a) 正当な 0x7D の生成と、その正しい値の実測**

平文送金では refund は 0 である（`rust/alloy-op-evm/src/post_exec/inspector.rs:252-256`：
tx 自身の `to` は EIP-2929 で intrinsic warm なので cold→warm 超過分を払っておらず
rebate は発生しない）。同一ブロック内で先行 tx が warm 化したスロットを
SLOAD するコントラクト（runtime `0x6000545000`）に 2 本入れて初めて生成された：

```
block 366 types=['0x7e', '0x2', '0x2', '0x7d']
  0x7D payload = 0xca01 82016e c5c402 8207d0
              = version 1, block 366, [SDMGasEntry{index:2, gas_refund:2000}]
```

`2000` は `inspector.rs:20` の `SLOAD_REWARM_REFUND` と完全一致する。
**正当な値が実測できたので、以後の偽造値は「正しい値との差」として提示できる。**

**(b) 偽造 0x7D の受理（単一エントリ）**

engine API を直接駆動し、`noTxPool = true` で EL を `PostExecMode::Verify` に
入れ、平文送金 1 本に `gas_refund = 21000`（= `evm_gas_used` 全額）を主張する
0x7D を載せた。**(a) の実測どおり、この tx の正しい refund は 0 である。**

```
CONTROL (0x7D なし, block 438)   user tx receipt: status=0x1 gasUsed=21000
  sender  -21,000,010,522,095    base +21,000,000,000,000
                                 oper        +10,500,000   seq +21,000

FORGED (0x7D あり,  block 439)   newPayload: VALID
                                 user tx receipt: status=0x1 gasUsed=0
  sender             -1,095      base                  +0
                                 oper                  +0   seq      +0
```

偽造 0x7D の raw：`0x7dca018201b7c5c401825208`。
`newPayload` は **VALID**、receipt の `gasUsed` は **0**。残る -1,095 wei は
送金額 1,000 wei と L1FeeVault 分 95 wei であり、L2 のガス代はゼロになった。

**(c) 1 本の 0x7D でブロック全体（5 tx）を全額 refund**

```
CONTROL (block 440)  gasUsed=148346  receipts=[21000]*5
FORGED  (block 441)  gasUsed= 43346  receipts=[0]*5   newPayload: VALID
        forged entries = [(1,21000),(2,21000),(3,21000),(4,21000),(5,21000)]
```

| | fee vaults 計 | senders 計 |
|---|---|---|
| honest | **+525,000,052,500,000** | -525,000,052,500,480 |
| forged | **0** | -480（L1FeeVault のみ）|

L2 手数料収入（base fee + priority fee + operator fee）が **100% 消滅**した。

**(d) 保存則は破れていない**

`rust/alloy-op-evm/src/block/mod.rs:711-730` の借方・貸方は一致する：
`sender += refund × effective_gas_price + operator_fee_delta` に対し、
`BASE_FEE_RECIPIENT -= refund × basefee`、
`beneficiary -= refund × (effective − basefee)`、
`OPERATOR_FEE_RECIPIENT -= operator_fee_delta`。
また上限は `refund <= evm_gas_used`（`:559-563`）なので、**当該 tx が実際に
支払った額を超えて加算されることはない。第三者の元本は減らない。**
したがって本件の損失は「手数料金庫が受け取るべき収入の全額喪失」であり、
利得は「送信者の残高に残る未払分」である。

**(e) 残った ETH の出金開始**

```
initiateWithdrawal: status=0x1 block=442
  tx  0xbc55bfbf3b718b26c3abe24c5ba2832c387a8053c9718a8c90d3dfbc34725715
  MessagePassed(0x02a52367…)
    nonce  0x0001…0000
    sender 0x23618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f
    target 0xb94441b6fb20776f61c97070e163d13dca055170
  sender balance 9,999,899,735,686,909,679,330 → 9,999,899,554,412,860,965,961
```

未払分 105,000,010,500,000 wei を指定先 `0xb94441b6Fb20776f61c97070E163D13DCA055170`
宛に出金開始した。残高は通常の L2 ETH であり、§3-7 で通した pipeline と同一の
経路に乗る。

再現物は `evidence/sdm-devnet/` に置いた
（`intent.toml` / `depset.json` / `sdm-start.sh` / `forge_postexec.py` /
`forge_multi.py` / `withdraw_retained.py`）。

---

## 4. 未実行の項目

| # | 項目 | 未実行の理由 |
|---|---|---|
| 8, 11, 12 | devnet 上の**正常** withdrawal 全行程 | **完了**（§3-7、すべて status 0x1）。ただし正常往復の control run であり、SDM 由来残高は含まない |
| — | SDM 有効な devnet 上での refund 偽造 | **完了**（§3-8、`newPayload: VALID` / `gasUsed 0`）|
| — | 偽造 refund で残った残高の出金開始 | **完了**（§3-8(e)、`status=0x1`、`MessagePassed` の target は指定先）|
| — | **同一チェーン上での L1 着金**（prove → 7 日 → finalize） | **未実行。** devnet-sdm には batcher / proposer / dispute game を立てていない。この 3 工程は §3-7 の devnet（L1 31337）で status 0x1 まで通っており、対象が「通常の L2 ETH 残高」である点は同一 |
| — | SDM refund が sender の**開始資産を超える**不正利益を生成すること | **不成立**（§3-8(d)。上限 `refund <= evm_gas_used` により当該 tx の支払額を超えない）|
| — | FeeVault / 共有 pool からの**純窃取**（第三者元本の移転） | **不成立**（§3-8(d)、借方貸方が一致）|
| — | 実 kona を dispute game に接続した再現 | permissionless FDG（gameType 0）の実装デプロイが必要。現 devnet は `gameImpls(0) = address(0)` |
| — | op-geth parity | 下記 5-2 参照 |

### 現時点の判定

| 対象 | 判定 |
|---|---|
| 正常 withdrawal pipeline | **Confirmed**（§3-7）|
| Verify が refund を再計算しない | **Confirmed**（§3-1、§3-8(b)）|
| 偽造 0x7D が canonical block として受理される | **Confirmed**（§3-8(b)(c)、`newPayload: VALID`）|
| L2 手数料収入を 100% 消滅させられる | **Confirmed**（§3-8(c)、実測 525,000,052,500,000 wei → 0）|
| L1 出金上限は lockbox 残高のみ | **Confirmed**（§3-4）|
| 偽造で残った残高が withdrawal に乗ること | **Confirmed（L2 側のみ）**（§3-8(e)）|
| 同一チェーン上での L1 着金までの連結 | **未実行**（工程自体は §3-7 で Confirmed）|
| sender の開始資産を超える不正利益 | **不成立**（§3-8(d)）|
| 第三者元本の純窃取 | **不成立**（§3-8(d)）|

**影響の正確な形**：本件は第三者の元本を奪う脆弱性ではない。
sequencer が自らの主張だけで L2 手数料収入を任意にゼロにでき、
fault proof がその主張を同じ主張と突き合わせるため検出されない、という
**権限設計と検証設計の欠陥**である。損失は手数料金庫の受取人（統治側）が負い、
未払分は送信者の L2 残高として残り、通常の withdrawal で L1 に出る。

手順・引数・アドレスは `devnet/WITHDRAWAL-RUNBOOK.md` に実測値で埋めてある。
証跡取得は `devnet/capture-withdrawal-evidence.sh` が receipt の
`status == 0x1` のみを成功として記録する。

---

## 5. 明示する限界と未決事項

### 5-1. permissioned game では反論経路が行使されない

現 devnet の `gameType = 1` は `PermissionedDisputeGame` であり、
`move` / `step` は `proposer()` / `challenger()` の 2 アドレスに限定される
（`21-26`）。したがってこの構成の `DEFENDER_WINS` は
「外部の正直者が反論を試みたが不能だった」ことを示さない。
**§1 の 3（循環による反論不能）を実チェーンで示すには
permissionless の `FaultDisputeGame`（gameType 0）が必要である。**

本資料では、この点を証明済みとしていない。

### 5-2. op-geth との差分（未決）

`op-geth`（`9ee3952a7`）を全走査した結果。

| 観点 | 結果 |
|---|---|
| 0x7D `PostExecTx` 型 | 存在（`core/types/post_exec_tx.go`、`Data []byte` のみ、58 行） |
| 使用箇所 | encode / decode / hash / receipt / signing の 5 ファイルのみ |
| `core/` 実行系の Karst 分岐 | **なし**。`IsKarst` の参照は genesis / ethconfig / backend の設定上書きのみ |
| `gasUsed()` | `st.initialGas - st.gasRemaining`（`849-851`）。refund による調整なし |
| 金庫加算 | `state_transition.go:719/725/732` で `st.gasUsed()` 基準 |
| 金庫からの引き落とし | **なし** |

同一の 0x7D payload に対し、op-geth は refund を無視し `evm_gas_used` 基準で
金庫に加算する。`alloy-op-evm` は `canonical_gas_used` 基準にしたうえで
金庫から引いて sender に戻す。**両者は異なる残高を計算する。**

ただし本資料はこれを finding として主張しない。SDM 有効チェーンで op-geth が
EL として使われるかを未確認のためである。確認すべきは、
(a) op-geth が `KarstTime` / `LagoonTime` 設定時に起動を拒否するか、
(b) superchain-registry における該当チェーンの EL 構成、
(c) op-node が EL 種別を検査するか。

### 5-3. 活性化ゲート（解決済み）

一次資料は Lagoon をゲートとしている。これは正しい。**表記の不一致は存在しない。**

`rust/alloy-op-evm/src/env.rs:36-41`（全文）

```rust
// Forks must be checked newest-first. Interop (op-revm's `INTEROP` spec) is activated by the
// Lagoon hardfork, which is newer than Karst, so Lagoon is checked before Karst.
check_forks! {
    // op-revm still names this spec `INTEROP`; Lagoon is the hard fork that activates it.
    is_lagoon_active_at_timestamp => INTEROP,
    is_karst_active_at_timestamp => KARST,
```

- **hardfork 名**：Lagoon
- **op-revm 内部の spec 名**：`INTEROP`（歴史的な命名がそのまま残っている）
- **その一つ前の fork / spec**：Karst / `KARST`
- 解決は newest-first なので、Lagoon が Karst より先に評価される

> Lagoon is the hardfork activation name; `INTEROP` is op-revm's internal spec
> identifier for the execution rules activated by Lagoon. Karst is the preceding
> fork and is checked afterward in newest-first resolution. No gate discrepancy
> remains.

活性化経路も一次資料の記述どおりである。

- genesis：`l2GenesisLagoonTimeOffset`（`op-chain-ops/genesis/config.go`）、
  `lagoonAtGenesis`（`op-chain-ops/interopgen/deploy.go`）
- 運用時：`--rollup.operator-sdm-opt-in` / `OP_RETH_OPERATOR_SDM_OPT_IN`、
  および admin RPC `admin_setOperatorSdmOptIn`（op-reth のビルドで存在を確認）

したがって、協調ハードフォークを要さず単一オペレータが有効化できるという
一次資料の主張は、コード上の経路として裏付けられている。

### 5-4. 統治側の停止手段は存在する

`AnchorStateRegistry.isGameClaimValid`（`320-342`）の内側には、
`DEFENDER_WINS` 以外に 3 つの独立した無効化条件がある。

| 条件 | 行 |
|---|---|
| blacklist | `241-243` |
| retirement timestamp（それ以前の全ゲームを一括無効化） | `248-252` |
| pause | `292-294`（`isGameProper` 内） |

`test_withdrawal_chain.py` はこの 3 つがいずれも finalize を阻止することを
実行して確認している。したがって「経路上に阻止する手段がない」という
記述は正確でない。阻止には統治側の介入が必要であり、
自動的には働かない、というのが正確な表現である。

### 5-5. 一次資料に含まれる、本資料が支持しない記述

| 記述 | 本資料の扱い |
|---|---|
| `docker-poc/shadow-protocol/src/main.rs` の `cmd_finalize` 出力 | **証跡として使用しない。** `149-155` は無条件の `println!` で、金額は argv 由来。実 RPC は読み取り 4 種のみ |
| `mainnet_damage.py` の 184,669 ETH | RPC 失敗時のハードコード既定値（`268-269`）。実測値ではない |
| `docker-poc/REPORT.md:102` の 184,669,180 ETH | 桁の誤り。`main.rs:138` の wei 値は 184,669.18 ETH |
| 17,280 ETH/day、約 10 日で枯渇 | stress parameters での試算。実測ではない |
| ETH Mainnet 上の redirect 詐欺との併記 | 一次資料が明記するとおり因果関係の主張はない。時間的緊急性の論拠としてのみ |

---

## 6. 再現手順

```bash
# 第1段：executor（Rust、実コード）
./scripts/build-sdm-repro.sh --assemble-only
cd .repro/optimism-sdm/rust
cargo test -p alloy-op-evm --lib block::tests::sdm      # 33 passed

# 第2段：権限迂回と全体チェーン（Python モデル）
cd sdm-fraudproof
python3 test_fraud.py               # 9 passed
python3 test_authority_bypass.py    # 6 passed
python3 test_withdrawal_chain.py    # 8 passed

# 第3段：L1 の出金上限（Solidity、実コントラクト）
cd .repro/optimism-sdm/packages/contracts-bedrock
cp ../../../../evidence/ETHLockboxDrainCeiling.t.sol test/L1/
forge test --match-contract ETHLockbox_DrainCeiling_Test    # 5 passed
```

環境の再構築は `devnet/HANDOVER-linux.md`。

---

## 7. 提出時の推奨

1. **§3-7 を「正常 withdrawal の control run」として提出する。**
   これを SDM による無権限資金生成の証拠に昇格させないこと。
   正常経路を端から端まで構築できたことは本物の成果であり、
   それ以上に見せる必要はない
2. **§5 をそのまま残す。** #82416 は critical 主張を `[NOT PROVEN]` と
   自ら書いて閉じられた。同じ形を避けるには、証明済みと未証明を
   分けたうえで、未証明を隠さないことが必要である
3. **complete exploit を成立させるには、SDM 有効な devnet が必要。**
   `lagoon_time` を設定した genesis で再デプロイし、L2 EL を op-reth
   （`--rollup.operator-sdm-opt-in`）にしたうえで、0x7D payload に
   偽造 refund を載せる block builder を用意する。これが揃えば
   「sender の開始資産を超える不正利益」を残高差分で測れる
4. **§5-1 を満たすには permissionless FDG が必要。** 現構成のままでは
   「反論不能」を実チェーンで示せない
5. **`resolve()` の permissionless 性を脆弱性として書かない。**
   呼び出し者は結果を選べず、liveness 設計と解される

---

## 8. 参照

- 一次資料：`docs/reports/VULNERABILITY_REPORT.md`
- 修正案：`patches/sdm-refund-trust-gap.patch`（基準 `a7ab3fd3c4`）
- 再現ハーネス：`scripts/build-sdm-repro.sh`
- devnet 手順：`devnet/HANDOVER-linux.md`、`devnet/WITHDRAWAL-RUNBOOK.md`
- 証跡取得：`devnet/capture-withdrawal-evidence.sh`
- Immunefi #82416（2026-06-19 Closed）
