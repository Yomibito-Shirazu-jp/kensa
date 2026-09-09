# 悪シーケンサー — パラメータ / 改ざん可否 / 最悪シナリオ

紛らわしいので、**「どこにある値か」で層を分ける**。層が違えば必要な立場も難易度も違う。

出典:
`[spec]` = [specs.optimism.io](https://specs.optimism.io/) /
`[docs]` = [rollup-deployment-configuration](https://docs.optimism.io/chain-operators/reference/rollup-deployment-configuration) /
`[実測]` = 2026-08-02〜03 に mainnet / fork から直接読んだ /
`[未確認]` = 本セッションで裏を取っていない /
`[提出]` = Immunefi 報告（#82416 = 2026-06-19 提出・同日 Closed） /
`[FIND-xxx]` = `engagement-optimism-bugbounty-2026-08-03/exploit/findings/` の finding（tier 付き）
あ
---

## 先に結論

| | |
|---|---|
| **Trust Gap 単体で必要な改ざん** | **ゼロ**。デフォルト設定のまま成立する |
| Trust Gap が他に与える効果 | 下の T2 / T3 の改ざん結果を **反証不能にする** |
| T2 / T3 単体 | L1 に記録が残り、検証者は正しく追従し、ガバナンスで止められる |

つまり Trust Gap は「新しいレバー」ではなく、**既存の全レバーの安全装置を外すもの**。

---

## T0. Trust Gap 本体 — 申告値（改ざんの痕跡が残らない唯一の層）

| 値 | 誰が入れるか | 検証者 | 最悪シナリオ | 出典 |
|---|---|---|---|---|
| SDM warming refund（tx type `0x7D` payload） | シーケンサがブロックに埋める | **同じ嘘を再現する**（下記の通り [POSSIBLE] 部分あり） | `canonical_gas_used` → `stateRoot` → fee settlement を掌握。`BASE_FEE_RECIPIENT` / `OPERATOR_FEE_RECIPIENT` から sender へ | `[提出]` #82416 / FIND-001 |

**改ざんの前提**: シーケンサ鍵（保有・侵害・共謀）。設定変更もアップグレードも不要。
ただし **Lagoon 稼働が条件**: `lagoon_time` は全21登録チェーンで `null`（`[実測]` mainnet-params.json / FIND-001 `[EVD-007]`）。現時点では発火せず、起動と同時に火が通る状態。

**金額の上限（厳密）**: ガードは `refund <= evm_gas_used` のみ → sender credit ≤ その tx の支払額。
直接効果は**手数料収入の蒸発**である。OP Mainnet 実測（chain 10, head 155,052,134, basefee 386 wei, scalar 0/0）に基づく offline 計算 `[EVD-018]` では protocol loss **0.000667 ETH/日**、gross value moved 3.938 ETH/日（priority 込み）。post-Lagoon 仮定（1 gwei basefee, scalar 5）では ≈1,728 ETH/日になるが、これは存在しない手数料環境の仮定である。
第三者元本や vault 既存残高（実測 計 ≈20.6 ETH）はこの primitive 単体では減らせない（FIND-001 / poc-index）。
「fee vault を drain できる」という表現はこの上限と矛盾するため使わない。FIND-001 の severity は fee 軸ではなく **stateRoot 完全性軸**（反証不能な偽造 root が finalize する）に依る（addendum-002 §2-3）。

**検証者の追認**: op-reth と kona（proof program）が同じ `OpBlockExecutor` の同じ Verify 分岐を走ることは `[CONFIRMED]`（FIND-002）。
「挑戦者は counter できず、`step` まで潜っても負ける」は **`[POSSIBLE]`** — 正直な op-challenger の実 run が未実施。
devnet で実証済みなのは「**誰も挑戦しなければ** forged root が finalize する」まで（addendum-82416-e2e §4）。

**検知**: L1 に矛盾が残らない。`compare_refunds` は debug replay crate にしか無く、executor / proof program の誰も呼ばない（FIND-003）。
**止める主体**: 存在しない（finalize 前なら Guardian レバーは有効 — ただし後述 FIND-010 の穴）。

---

## T1. SystemConfig — L1 トランザクションで変更できる（owner 権限）

spec が列挙している setter はこの8つだけ `[spec]`:
`setUnsafeBlockSigner` / `setBatcherHash` / `setGasConfigEcotone` / `setGasLimit` /
`setEIP1559Params` / `setOperatorFeeScalars` / `setMinBaseFee` / `setDAFootprintGasScalar`

| # | パラメータ | 制限 | 最悪シナリオ | Trust Gap と組むと |
|---|---|---|---|---|
| 1 | `unsafeBlockSigner` | owner のみ | 偽の unsafe block に署名して P2P に流す。ユーザーは実体のない残高で取引 | **単独なら derive 時に reorg されて消える。Trust Gap があると safe に昇格し、消えない** |
| 2 | `batcherHash` | owner のみ | batch を出さない / 選んで出す → L2 凍結・検閲 | 出した嘘が確定する |
| 3 | `gasLimit` | `min <= x <= max` `[spec]`。実測 min 21M / max 500M / 現行 40M（min=max に固定）`[実測]` | 極小化して清算タイミングを狙った検閲 | 同上 |
| 4 | `baseFeeScalar` / `blobBaseFeeScalar` | 明示上限なし | L1 費用の水増し請求、差額の搾取 | 会計の矛盾が検知されない |
| 5 | `operatorFeeScalar`(uint32) / `operatorFeeConstant`(uint64) | 式は `gas × scalar ÷ 10⁶`。理論上限約 **4,295倍**。現行は scalar=0 / constant=0 で無効化中 `[実測]` | 1回の送金で全額を手数料として没収 | 同上 |
| 6 | `eip1559Params`（denominator / elasticity） | `>= 1` のみ `[spec]`。現行 denominator 250 / elasticity 2 `[実測]` | 少しの混雑でガス代が万倍に。パニック誘発 | 同上 |
| 7 | `minBaseFee` | 標準最大 10,000,000,000 wei `[docs]` | 優先手数料オークションの操作 | 同上 |
| 8 | `daFootprintGasScalar` | 推奨 400 `[docs]` | ブロックに入るデータ量を絞る → 検閲 | 同上 |

**共通の性質**: L1 に `ConfigUpdate` イベントが残る。検証者は新しい値に**正しく追従する**。
つまり「見える濫用」。Trust Gap と違い、監視とガバナンスで止められる余地がある。

---

## T2. rollup config / デプロイ設定 — L1 tx では変えられない

`[docs]` のページにある値。全ノードが同じ `rollup.json` を持つ必要があるので、
変更は実質ハードフォーク。**単独の L1 tx では届かない。**

| # | パラメータ | docs の記述 | 最悪シナリオ |
|---|---|---|---|
| 9 | `maxSequencerDrift` | "the number of seconds after the L1 timestamp of the end of the sequencing window that batches must be included"（現行 600秒 `[実測]`） | 巨大化 → L2 の時計を**未来へ**進める。ベスティング解除・オークション終了・タイムロック・清算期限の前倒し。※過去へは戻せない（下記） |
| 10 | `sequencerWindowSize` | "the number of L1 blocks per sequencing window"（現行 3,600 `[実測]`） | 強制インクルード（force include）までの猶予を伸ばす → 検閲の持続時間を延長 |
| 11 | `channelTimeout` | "the number of L1 blocks that a frame stays valid"（既定 50） | フレーム有効期間の操作 |
| 12 | `l2BlockTime` | "the number of seconds between each L2 block"（現行 2秒 `[実測]`） | ブロック生成間隔の操作 |
| 13 | `l2GenesisBlockGasLimit` | 標準最大 200,000,000 | 初期上限の設定 |
| 14 | `useCustomGasToken` + `gasPayingTokenName` / `Symbol` | "a flag to indicate that a custom gas token should be used" | ガス通貨を無価値な独自トークンに固定 → 経済圏の乗っ取り |
| 15 | `nativeAssetLiquidityAmount` | "the amount of liquidity to pre-fund the NativeAssetLiquidity contract with" | 初期流動性の操作 |
| 16 | `batchInboxAddress` | "the L1 account that batches are sent to" | 投函先の付け替え |
| 17 | `p2pSequencerAddress` | "the address of the key the sequencer uses to sign blocks on the P2P layer" | #1 と同じ（初期値側） |
| 18 | `batchSenderAddress` | "can be updated later via SystemConfig on L1" | #2 と同じ（初期値側） |

### 9 について — 方向は「未来」だけ

derivation の制約式 `[spec]`:

> "l1_origin.timestamp <= block.timestamp <= max_l2_timestamp,
> where max_l2_timestamp = max(l1_origin.timestamp + max_sequencer_drift, prev_l2_timestamp + l2_block_time)"

下限が `l1_origin.timestamp` で固定。`max_sequencer_drift` を大きくしても動くのは**上限だけ**。
`prev_l2_timestamp + l2_block_time` で単調増加も強制される。**過去への巻き戻しは不可。**

---

## T3. 出金の待ち時間 — これも運営者のパラメータだった

| # | パラメータ | docs の記述 | 実測値（OP Mainnet） |
|---|---|---|---|
| 19 | `proofMaturityDelaySeconds` | "the number of seconds that a proof must be mature before it can be used to finalize a withdrawal" — Set by: Chain operator | **604,800秒 = 7日** `[実測]` |
| 20 | `disputeGameFinalityDelaySeconds` | "an additional number of seconds a dispute game must wait" — Set by: Chain operator | **302,400秒 = 3.5日** `[実測]` |
| 21 | `finalizationPeriodSeconds` | "generally set to 1 week" — Guidance: "**12 seconds on testnets**, 7 days on production" | — |
| 22 | `faultGameWithdrawalDelay` | "the number of seconds that users must wait before withdrawing ETH from a fault game" | — |

**7日はプロトコルの定数ではなく、運営者が選んだ値。** テストネットでは12秒。
デプロイ済みコントラクトの immutable なので変更にはアップグレードが要るが、
「誰にも縮められない物理法則」ではない。

---

## T4. 争議の側 — パラメータではなく構造

| # | 対象 | spec 引用 | 最悪シナリオ |
|---|---|---|---|
| 23 | ゲームの検査範囲 | "the game itself doesn't verify claim contents — it only settles disputes at maximum depth through VM execution via the `step` function" | 最終審が同じ program。潜っても負ける |
| 24 | 挑戦者の根拠 | "relies on ... a synced, **trusted rollup node** as well as a trace provider" | 反証の出どころが疑う相手と同経路 |
| 25 | 保証金 | "the minimum bond depends only on the position of the move that's added" | 守る額と無関係。0.08 ETH `[実測]` で 199,664 ETH `[実測]` の root を立てられる |
| 26 | 沈黙の扱い | "A move ... is no longer possible once ... `MAX_CLOCK_DURATION` seconds" | 異議なし = 正しい |
| 27 | 金庫の上限 | `value <= address(this).balance` のみ。チェーン別台帳なし | 他チェーンの預け分まで射程 `[実測]` |

---

## まとめ表

| 層 | 件数 | 改ざんに必要な立場 | 痕跡 | 検証者 | 止められるか |
|---|---|---|---|---|---|
| T0 Trust Gap | 1 | シーケンサ（+ Lagoon 有効化） | **残らない** | **追認する**（推論・FIND-002 `[POSSIBLE]`） | 検知不可 / payout は finalize 前のみ可 / anchor 昇格後は **不可**（FIND-010） |
| T1 SystemConfig | 8 | owner（L1 tx） | ConfigUpdate イベント | 正しく追従 | ガバナンスで可 |
| T2 rollup config | 10 | 全ノード合意（実質ハードフォーク） | 設定変更 | 正しく追従 | 可 |
| T3 出金遅延 | 4 | コントラクトアップグレード | アップグレード | — | 可 |
| T4 争議の構造 | 5 | 不要（構造） | — | — | 設計変更が必要 |

**T1〜T3 はすべて「見える」。T0 と T4 だけが見えない。**
そして T0 があると、T1〜T3 で作った不正な状態が **反証不能になる**。

---

## T5. シーケンサー権限インベントリ — 権限の体系化

T0〜T4 は「パラメータ / 設定」の棚卸しだった。ここでは **シーケンサー鍵単体で実際に何ができるか** を、ソース（`op-node` / `op-reth` / `kona` / spec / `SystemConfig.sol`）と照合して体系化する。
T1〜T3 と重なる部分は「誰の権限か」を分離するための再分類。

### A. トランザクション選択・順序（policy、consensus 非強制）

| 権限 | 可否 | 制約 | 出典 |
|---|---|---|---|
| user tx の完全検閲（自分の tx だけ入れる） | **可** | tx selection は policy | spec Sequencer / op-geth miner/worker.go |
| user tx の並べ替え（MEV・フロントラン） | **可** | nonce 順のみ強制 | spec Sequencer / op-geth |
| 空ブロック生成（deposit のみ） | **可** | `max_sequencer_drift` 超過時は強制 | spec Derivation / batches.go |
| 自分の tx を sender として含める | **可** | sender 制限なし、標準 EVM validation のみ | op-node/rollup/sequencer/ に制限コードなし |
| deposit tx (0x7E) の除外 | **不可** | derivation が L1 から強制挿入 | attributes.go "deposits may never be ignored" |
| force inclusion の回避 | **不可** | `sequencerWindowSize`（実測 3,600）経過後は自動 derive | batches.go / batch_queue.go |

### B. ブロックヘッダ（derivation-constrained、producer-trusted でない）

| フィールド | 制約 | 出典 |
|---|---|---|
| `gasLimit` | SystemConfig から derive、`min ≤ x ≤ max` で validate | attributes.go:206 / op-reth consensus lib.rs:184 |
| `baseFee` | EIP-1559 で parent から validate | op-reth consensus lib.rs:200 |
| `timestamp` | L1 から derive、parent timestamp との関係を validate | attributes.go:209 / op-reth consensus lib.rs:196 |
| `extraData` | **サイズのみ validate**。中身（Holocene/Jovian の EIP-1559 params / min_base_fee）は producer が設定、decode 後に使用 | op-reth consensus lib.rs:183 / OpPayloadAttributes:42-52 |

### C. 申告値（producer-declared、verifier が再計算せず採用）

| フィールド | tx type | 再計算 | ガード | 出典 |
|---|---|---|---|---|
| `SDMGasEntry.gas_refund` | 0x7D | **なし** | `refund ≤ evm_gas_used`、≠0、deposit/post-exec 宛不可 | post_exec.rs:30-35 / mod.rs:534-567 |

**0x7D 以外の synthetic tx type は存在しない**（`tx_type.rs:31-32` で ALL = [Legacy, Eip2930, Eip1559, Eip7702, Deposit, PostExec]）。0x7F なし。

### D. 不可（構造的に不可能）

| 操作 | 理由 |
|---|---|
| L1 データの偽造 | deposit は L1 calldata/event 由来 |
| 過去への timestamp 巻き戻し | `l1_origin.timestamp ≤ ts` + `prev_ts + l2_block_time` で単調増加 |
| stateRoot の直接操作 | 実行結果の関数でなければならない（FIND-001 が唯一の例外） |
| 共有 ETHLockbox への勝手な参加 | `authorizePortal` は ETHLockbox の ProxyAdmin owner のみ（ソース確認済み） |

### E. 悪用への道筋（権限から導く）

シーケンサーが持つ**状態に影響を与える**権限は実質2つ:

1. **tx 選別・順序・自己 tx 挿入** — 検閲・MEV。ただし force inclusion（12時間後）が上限
2. **0x7D payload の gas_refund 申告** — FIND-001。stateRoot に影響する唯一の producer-declared 値

**1 は L1 データに錨定されているため反証可能**。**2 は L1 データから再導出できないため反証不能**（FIND-002）。この非対称が Trust Gap の本体。

金額上限は `refund ≤ evm_gas_used` で手数料スケールに固定されるため、**シーケンサー権限の範囲内では lockbox 級の大金を L2 状態に直接作る primitive は存在しない**。大金への到達には challenger の不在（FIND-009 の single off-chain dependency）が別途必要で、それはシーケンサー権限の外。

---

## T6. Lagoon 前に即座に有効な攻撃面 — FIND-008

T0（Trust Gap）は Lagoon 活性化が条件であり、現時点では発火しない。しかし **FIND-008 は Lagoon 不要で現行 OP Mainnet で即座に有効**である。

### FeeVault zero-recipient — 設定ミスの不可逆化

`FeeVault.sol` の `recipient` には3つの writer がある。guard があるのは1つだけ:

| writer | zero-address guard | 行 |
|---|---|---|
| `initialize(address _recipient, …)` | **なし** | 84-96 |
| `setRecipient(address _newRecipient)` | **なし** | 115-122 |
| `setWithdrawalRoute(address _newRecipient, …)` | `require(_newRecipient != address(0))` | 142-154 |

**攻撃の成立**:

1. ProxyAdmin owner が `setRecipient(address(0))` を実行（L2 コントラクトの直接呼び出し）
2. 金庫に `minWithdrawalAmount` 以上の残高が溜まる（通常運用で自動的に溜まる）
3. **誰でも** `withdraw()` を呼べる（permissionless）→ `SafeCall.send` は `call` to `address(0)` で success を返す → ETH が永久に消滅

**Lagoon 不要の理由**: この経路は 0x7D / SDM / post-exec refund を一切経由しない。`FeeVault.sol` の標準的な `withdraw()` パスのみで完結する。

**不可逆性**:
- `withdraw()` は permissionless なので、owner がミスに気づく前に第三者が確定させられる
- `L2ContractsManager` の upgrade path は `initialize` を replay するため、zeroed recipient は upgrade でもリセットされない
- 4つの金庫（BaseFee / L1Fee / SequencerFee / OperatorFee）すべてが同じパターン

**影響の範囲**: 金庫に溜まった手数料収入の全額消滅。第三者の L2 残高（元本）には影響しない。

**FIND-008 が INFO 扱いの理由**: ProxyAdmin owner は設計上完全に信頼されている役割。trust boundary 自体は破れていない。しかし `withdraw()` が permissionless である点が、owner の設定ミスを**第三者が確定させる**経路を作っている。

**T0 との関係**: なし。独立した攻撃面。T0 が stateRoot の偽造を反証不能にするのに対し、FIND-008 は設定ミスの不可逆化。両者は異なる層の欠陥だが、**Lagoon 前に実行可能**という点で FIND-008 だけが即座に有効。
