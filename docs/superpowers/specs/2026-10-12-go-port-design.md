# PatchTriage Go 移植 設計書（フェーズ1：トリアージ完了まで + GUI）

- 作成日: 2026-10-12
- 移植元: `C:\Users\iniad\patchtriage`（Python 0.6.0）。**移植元は読み取り専用。一切変更しない**（fixture/データはこのリポジトリへコピーする）。
- 移植先: このリポジトリ（`PatchTriage-go`）

## 1. 目的と背景

Python 製 PatchTriage を Go に移植する。PatchTriage はスキャナ結果・SBOM と対象システムの文脈から、CERT/CC SSVC Deployer モデル（`ssvc:DT_DP:1.0.0`）で決定論的にパッチ適用判断（Immediate / Out-of-Cycle / Scheduled / Defer）を下すツール。フェーズ1では「トリアージ完了まで」＝取り込みから判定・計画・レポート出力までと、既存の Web GUI を動かすところまでを移植する。

## 2. ゴール / 非ゴール / アンチゴール

### ゴール（フェーズ1）
1. CLI `run` / `verify` / `demo` / `serve` が Python 版と同じ判断を出す。
2. パイプライン: ingest → dedup → context(inventory) → enrich → SSVC → audit → BOD 26-04 → plan → evaluate → report(JSON + 自己完結 HTML)。
3. 入力: Trivy JSON、Grype JSON、osv-scanner JSON、CycloneDX / SPDX SBOM（OSV.dev で解決）。
4. 証拠: EPSS、CISA KEV、CISA Vulnrichment、NVD、ベンダー（MSRC / RHSA / USN / Debian / GHSA / Exploit-DB）、ディスクキャッシュ、オフライン demo 用スナップショット。
5. GUI: Python 版の単一ページ（`webapp/page.py` の HTML/JS）を**そのまま**埋め込み、同じ HTTP API 契約を Go の `net/http` で提供する（匿名セッション分離、ターゲット登録、アップロード、非同期ジョブ、SSVC 入力レビュー、レポート表示）。
6. JSON（CLI の `report.json`、GUI の API レスポンス・サマリ）のフィールド名と値の表現を Python 版と一致させる（GUI の JS を無改変で再利用するための必須条件）。

### 非ゴール（フェーズ2以降に回す）
- AI 説明バックエンド（`ai` / `cascade` / Anthropic・OpenAI プロバイダ、`setup` の API キー管理）。フェーズ1は `rules`（決定論 SSVC）のみ。
- リポジトリ取り込み（GitHub Dependency Graph SBOM、ローカル clone + osv-scanner）、`versions.py` のレジストリ問い合わせによる制約→具体バージョン解決、fleet import（GitHub org 列挙）。
- `remediate`、対話ウィザード `start`、`benchmarks/`。
- Docker / CI 設定。

### アンチゴール（動いても失敗とみなすもの）
- SSVC / BOD の結果が Python 版と1件でも食い違う。
- 判定表を閾値や重み付けスコアで近似する。表は全行を明示的に持つ。
- unknown 入力・既定値適用・矛盾・要確認フラグ・取得失敗を黙って捨てる（「証拠なし」を「安全」と扱う）。
- 不要なファイル分割、冗長なラッパー、使われない抽象化（ユーザー要望：ファイルを不用意に増やさない）。
- 移植元リポジトリへの書き込み。

## 3. 制約

- Go は winget で導入した最新安定版。`go.mod` の module path は `github.com/d01ki/PatchTriage-go`（リモート https://github.com/d01ki/PatchTriage-go と一致させる）。
- 依存は標準ライブラリ優先。外部依存は YAML 読み込みの `gopkg.in/yaml.v3` のみ。CLI は `flag` + サブコマンド手書き（cobra 不使用）。PEP 440 / Maven / Debian / SemVer のバージョン比較も自前実装。
- 移植元 CLAUDE.md / `.claude/rules/` の決定整合性ルールを引き継ぐ（証拠・決定論的判断・AI 説明の分離、KEV は木をバイパスしない、Automatable は脆弱性固有、BOD は別ポリシー、ネットワークのタイムアウト/リトライ/並列/サイズ上限、信頼できない入力のエスケープ、秘密情報をログに出さない）。
- 生成物（レポート、キャッシュ）はコミットしない。

## 4. ディレクトリ構成（ファイル数を絞った最終案）

Python 側の約33モジュール（フェーズ1対象範囲）を、凝集度で約20ファイルにまとめる。`pkg/` は外部公開の必要がないため使わず、すべて `internal/` に置く。

```
PatchTriage-go/
├── go.mod / go.sum
├── cmd/patchtriage/main.go        # サブコマンド run / verify / demo / serve（Python cli.py の該当部分）
├── internal/
│   ├── model/
│   │   ├── model.go               # Package, Asset, RawFinding, Finding, Enrichment, VendorAdvisory,
│   │   │                          # Severity, Triage 結果型, normalize_ecosystem, parse_purl
│   │   └── version.go             # CompareVersions（SemVer / PEP 440 / Maven / Debian / natural）
│   ├── ingest/
│   │   ├── scanner.go             # Trivy / Grype / OSV の入力用 struct、変換、形式判別、Load
│   │   ├── osv.go                 # OSV レコード照合（fixed 選択・範囲判定）と OSV.dev クライアント
│   │   ├── sbom.go                # CycloneDX / SPDX 部品抽出、カバレッジ記録
│   │   ├── dedup.go               # 相関・統合
│   │   └── inventory.go           # assets.yaml の適用（Python context.py）
│   ├── enrich/
│   │   ├── enrich.go              # EPSS / KEV / NVD / Vulnrichment、キャッシュ、スナップショット
│   │   └── vendors.go             # MSRC / RHSA / USN / Debian / GHSA / Exploit-DB
│   ├── decision/
│   │   ├── ssvc.go                # Deployer 推論・判定表・Human Impact 表・並び順キー
│   │   └── bod2604.go             # cisa:DT_BOD2604:1.0.0 と resolve_effective
│   ├── pipeline/
│   │   ├── assess.go              # パイプライン統括、カバレッジ統合、結果メッセージ
│   │   ├── audit.go               # 機械監査
│   │   ├── plan.go                # Action 生成・ランキング
│   │   ├── evaluate.go            # 順位付け比較（evalcmp）
│   │   └── presentation.go        # 優先度定義・根拠表示・decision quality
│   ├── report/
│   │   ├── report.go              # JSON レポート、HTML 描画（html/template）
│   │   └── report.html.tmpl       # embed
│   ├── web/
│   │   ├── server.go              # ルーティング、セッション cookie、ジョブ管理、上限
│   │   ├── store.go               # ターゲット登録・ワークスペース・成果物保存（Python targets.py）
│   │   ├── runner.go              # 1ターゲット実行とサマリ生成、fleet サマリ集約
│   │   └── page.html              # page.py の _TEMPLATE を無改変で抽出（embed）
│   └── validation/verify.go       # 72経路 / 16組合せ / 再現性 / 改ざん検出
├── data/
│   ├── data.go                    # //go:embed で demo データと検証表を公開
│   ├── demo_*.json, demo_assets.yaml, ssvc_validation.json
│   └── fixtures/{trivy,grype}_sample.json
└── testdata/                      # 移植元 tests/fixtures のコピー + Python 版から生成した golden JSON
```

テストは各パッケージの `*_test.go`（表駆動）。

### Python → Go 対応表

| Python | Go |
|---|---|
| models.py | internal/model/model.go |
| plan.py の compare_versions 系 | internal/model/version.go（ingest と plan の双方が使うため model 側へ。循環 import 回避） |
| ingest/parsers.py | ingest/scanner.go + ingest/osv.go |
| ingest/sbom.py | ingest/sbom.go（OSV.dev 通信部分は osv.go） |
| dedup.py / context.py | ingest/dedup.go / ingest/inventory.go |
| enrich/clients.py / vendors.py | enrich/enrich.go / enrich/vendors.go |
| ssvc.py / bod2604.py | decision/ssvc.go / decision/bod2604.go |
| triage/engine.py（rules のみ） | decision/ssvc.go の `TriageFromAssessment` に吸収 |
| triage/audit.py, plan.py, evalcmp.py, presentation.py, assess.py | pipeline/*.go |
| report/html.py + cli._emit の JSON | report/report.go + report.html.tmpl |
| webapp/server.py, targets.py, runner.py, page.py, fleet.aggregate_fleet | web/*.go |
| validation.py | validation/verify.go |

## 5. データ構造設計

### 5.1 二層構造
1. **入力用 struct（スキャナごと）**: ネイティブ JSON を受けるだけの型。`ingest/scanner.go` 内に非公開で定義。Python の `dict.get()` 相当の寛容さを保つ。
   - 省略可能な数値は `*float64`。
   - Trivy `CVSS` は `map[string]struct{V2Score, V3Score, V40Score *float64}`。
   - Grype `source.target` は文字列とオブジェクトの両方がありうるため `json.RawMessage` で受け、文字列なら文字列として、オブジェクトなら `userInput` → `imageID` の順で読む。
   - OSV レコードの `affected` / `ranges` / `events` は照合ロジックで使うため型付けする（`Event{Introduced, Fixed, LastAffected, Limit *string}`。`introduced` の有無を区別する必要があるのでポインタ）。
   - 形式判別（sniff）は Python と同じく `map[string]json.RawMessage` でトップレベルキーを見る。
2. **正規化モデル（`internal/model`）**: Python の pydantic モデルと1対1。JSON タグは Python の snake_case フィールド名と同一。

### 5.2 型の方針
- 列挙値は文字列型の定数（`type SystemExposure string`）。JSON 値が Python と一致する。
- 3値の bool（`internet_exposed`, `reachable`, `runtime_observed`）は `*bool`。Python の `Optional[float]` は `*float64`、`Optional[str]` は `*string`。
- `Asset` の SSVC / ポリシー文脈フィールドは、Python の validator と同じ正規化（小文字化、`-` を `_` に、bool は yes/no に）を行うコンストラクタ / `UnmarshalJSON` で検証する。
- `Finding.Triage` は Python では dict。Go では型付き `*Triage{Priority, Action, Rationale, SuggestedDeadlineDays, Backend, SSVC *decision.Assessment, BOD2604 *decision.BODResult, Effective *decision.Effective}` とし、JSON 出力時のキー（`priority`, `action`, `ssvc`, `bod2604`, `effective` 等）を Python と一致させる。`model` が `decision` を import すると循環するため、`Triage` と SSVC / BOD の結果型は `model` パッケージに置き、`decision` は計算ロジックのみ持つ。
- `RawFinding.Raw` は `json.RawMessage` として保持し、JSON 出力からは除外（`json:"-"`）。
- 時刻は `time.Time`（UTC）。Python の `model_dump(mode="json")` と同じ ISO 8601 表現で出力する。

## 6. SSVC 判定フロー

各判断点は「上から順に評価し、最初に確定したものを採用」。各値には `DecisionPoint{key, version, value, label, confidence, source, evidence[], inferred, needs_confirmation}` で出所を残す。

| 判断点 | 優先順位 |
|---|---|
| Exploitation (E 1.1.0) | ① KEV 掲載 → Active（分析者入力で下げられない。矛盾は要確認にして証拠に記録） ② 分析者確定入力 ③ Vulnrichment（`none` なのに exploit 参照ありなら Public PoC・要確認） ④ exploit 参照あり → Public PoC ⑤ None（exploit 検索が完了していれば MEDIUM、未完了なら LOW かつ要確認） |
| System Exposure (EXP 1.0.1) | ① 資産台帳 ② 旧 `internet_exposed`（true→Open / false→Controlled、要確認） ③ 既定値 Open（要確認） |
| Automatable (A 2.0.0) | ① 分析者入力 ② 資産台帳 ③ Vulnrichment ④ CVSS v4 の `AU` ⑤ 既定値 Yes（要確認） |
| Mission Impact (MI 2.0.0) | ① 資産台帳 ② criticality からの読み替え（要確認） ③ 既定値 MEF Support Crippled（要確認） |
| Safety Impact (SI 2.0.1) | ① 資産台帳 ② 既定値 Marginal（要確認） |
| Human Impact (HI 2.0.2) | 公式16通りの表（Safety × Mission）。確度は MI と SI の低い方 |
| Technical Impact (TI) | Vulnrichment の値か Unknown。Deployer の判定には使わない（BOD 用の補助情報） |

判定は `deployerTable[(E, EXP, A)][HIの序数]` で行う（18行×4列を明示的な map で保持）。そこから `P1〜P4` と期限（3 / 14 / 30 / 90日）を引き、推奨アクションを決める（fix の有無で `mitigate` / `patch_*` / `investigate` / `monitor` に分岐）。全体の確度は全判断点の最小値。

その後 BOD 26-04 を別に評価する。16行の表を使い、未確定の入力は全候補を展開して最も緊急な候補を provisional とする。最後に `resolve_effective` の5ルールで実効期限を決める。SSVC の結果は書き換えない。

並び順は ordinal キーのみで決める。順に priority、E、HI、EXP、A、EPSS、CVSS で、スコアの加算はしない。

## 7. 検証方針（同一判断の保証）

1. **判定表の適合性**: `data/ssvc_validation.json`（移植元から無改変コピー）で72経路と16組合せを表駆動テストする。BOD は移植元 `tests/fixtures/bod2604_decision_table.json` の16行。期待値をエンジン自身から生成しない。
2. **Python 版を正解とした golden 比較**: 移植元を変更せずに、一時 venv に `pip install` して Python 版で demo と fixture（trivy / grype / sbom）をオフライン（snapshot）実行する。その JSON を `testdata/golden/` に保存し、Go 版の出力と比較する。比較では `enriched_at` や `detected_at` などの時刻を除き、findings / actions / evaluation / response_policy / coverage を一致させる。
3. **移植元の pytest のうち対象範囲のもの**を Go の表駆動テストへ移す（test_ssvc, test_bod2604, test_versions, test_sbom, test_pipeline, test_assess, test_accuracy_core, test_decision_quality, test_coverage_messages, test_vulnrichment, test_vendor_advisories, test_enrichment_clients, test_cache_isolation, test_validation, test_webapp の対象部分）。ネットワークは `httptest` で偽装し、実ネットワークを使うテストは行わない。
4. **GUI**: `serve` を起動し、ブラウザで「demo → Run → Decision path / Action queue / Evidence / Review inputs → 入力変更して再実行 → レポート表示」の流れを確認する。
5. `patchtriage verify` の出力に含まれる `decision_fingerprint` は Python 版と一致しなくてよい（エンジンのソースのハッシュを含むため）。ただし決定内容の一致は 2 で担保する。

## 8. GUI の扱い

- `page.html` は `page.py` の `_TEMPLATE` を無改変で抽出する。Python 側が埋め込んでいる値（Human Impact 行列、ラベル辞書）は、Go の判定表から生成して同じプレースホルダへ差し込む。
- API は Python 版と同じパスとレスポンス形にする: `/`, `/api/config`, `/api/targets`, `/api/summaries`, `/api/jobs`, `/api/jobs/{id}`, `/api/demo`, `/report/{id}`, `/api/targets/{id}/context|ssvc-inputs|source|runs|run`, `/api/fleet/summary`。
- フェーズ1で未移植の機能（`/api/targets/{id}/repository`, `/api/fleet/import`）は、GUI の JS を変えずに `501` と短いエラー文（「この Go 版ではまだ利用できません」）を返す。JS は既存のエラー通知で表示する。`/api/config` の `capabilities` から `github-repository-sbom` と `fleet-import` を外し、`backends` は `["rules"]` のみにする。
- `/api/fleet/summary` は保存済みサマリを集約するだけでネットワークを使わないため移植する（2ターゲット以上でサイドバーに表示される）。
- セッション分離（ランダムな HttpOnly cookie、6時間で失効）、アップロードサイズ上限、ジョブ同時実行上限、入力リビジョンによる古い結果の無効化は Python と同じ環境変数名と既定値で実装する。

## 9. ビルダーに任せる事項

- 各ファイル内の関数分割、エラー型の細部。
- HTTP クライアントのリトライ・バックオフの実装方法（タイムアウト、上限、Retry-After の尊重は必須）。
- キャッシュの保存場所（Python と同じ `~/.cache/patchtriage` を使う。ただし Go 版と Python 版のキャッシュ互換性は不要なので、サブディレクトリを分けてよい）。

## 10. 私の判断で決めた点（要確認）

1. module path `github.com/d01ki/PatchTriage-go`。
2. 外部依存は `yaml.v3` のみ。CLI フレームワークは使わない。
3. 制約付きバージョン（`>=1.2` など）の SBOM 部品は、フェーズ1ではレジストリ解決せず、Python と同じ「未解決バージョンとして skipped・coverage incomplete」で扱う（レジストリ解決はリポジトリ取り込みとあわせてフェーズ2）。
4. ベンダー証拠（Exploit-DB を含む）はフェーズ1に含める。既定の `auto` で Exploitation の判定に影響し、同一判断の保証に必要なため。
5. 監査（audit）は rules のみでも移植する。`verify` の改ざん検出と GUI サマリの `audit_verified` が依存しているため。
6. GUI の未移植機能はボタンを残し、501 エラーで知らせる（page.html を改変しないため）。
