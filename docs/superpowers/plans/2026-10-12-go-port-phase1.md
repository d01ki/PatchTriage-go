# PatchTriage Go 移植 フェーズ1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Python 版 PatchTriage 0.6.0 の「取り込み〜SSVC/BOD 判定〜計画〜レポート」と Web GUI を、同一判断を出す Go 実装として移植する。

**Architecture:** `internal/` 配下 9 パッケージ（model / ingest / enrich / decision / pipeline / report / web / validation + data）。各タスクは対応する Python モジュールを**挙動の正**として忠実に移植し、Python 版の pytest を Go の表駆動テストへ移し、最後に Python 版で生成した golden JSON と出力を突き合わせる。

**Tech Stack:** Go 1.27.0（`C:\Program Files\Go\bin\go.exe`）、標準ライブラリ、`gopkg.in/yaml.v3`。golden 生成のみ Python 3.10（一時 venv）。

**Spec:** `docs/superpowers/specs/2026-10-12-go-port-design.md`

## Global Constraints

- 移植元 `C:\Users\iniad\patchtriage` は**読み取り専用**。書き込み・`pip install -e`・pytest 実行によるキャッシュ生成もしない（venv はスクラッチパッドに作り、移植元は `pip install <path>` の非 editable で読むだけ。`.pytest_cache` を作らない）。
- module path: `github.com/d01ki/PatchTriage-go`。
- 外部依存は `gopkg.in/yaml.v3` のみ。CLI は `flag`。
- JSON のキー名・列挙値・null/空の表現は Python の `model_dump(mode="json")` と一致させる（GUI JS を無改変で使うため）。`Optional` → ポインタ + `omitempty` なし（Python は null を出力する）。`list` は nil ではなく空スライスで `[]` を出力。
- 判定表（Deployer 18×4、Human Impact 16、BOD 16）は全行を明示した map / 配列で持つ。式で近似しない。
- unknown・既定値適用・矛盾・要確認・取得失敗は値として保持し出力する。
- 共有スライスは `[]*model.Finding`（パイプラインはその場で書き換える）。
- ファイルは設計書 §4 のもの以外を作らない（`_test.go` と `testdata/` を除く）。
- bash から実行する場合は `export PATH="/c/Program Files/Go/bin:$PATH"`。
- コミットは各タスク末尾。メッセージ末尾に `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`。ブランチ `go-port-phase1` 上で作業する（main へ直接コミットしない）。

## Review Focus

1. **Python 版にない JSON 形状の差**（null vs 省略、`[]` vs `null`、float の `1.0` vs `1`、時刻形式）— GUI がサイレントに壊れる。Task 11 の golden 比較と Task 14 のサマリ golden で検出。
2. **不正・切り詰められた入力 JSON / 未知形式** — 明確なエラーで終了し、パニックしない。Task 3 に `TestLoadRejectsMalformedAndUnknown`。
3. **ネットワーク失敗・タイムアウト・429** — 取得成功分を保持し、失敗を `retrieval_errors` / `retrieval_status` に残し、KEV 失敗を非掲載扱いにしない。Task 8 に `TestEnrichKEVFailureIsNotAbsence`、`TestEnrichRetriesOn429ThenRecords`。
4. **GUI の信頼できない入力**（巨大アップロード、不正 target id、他セッションの id、HTML 注入）— 上限・404・エスケープ。Task 15 に `TestServerRejectsOversizeAndForeignSession`、Task 12 に `TestHTMLEscapesUntrustedText`。
5. **Windows パス・改行**（CRLF 入力、`C:\` パス）— 読み込み・キャッシュ・ワークスペースが動く。Task 3 に `TestLoadCRLFAndBOM`（UTF-8 BOM 付き JSON も受理）。

---

### Task 1: ブートストラップ + model パッケージ

**Files:**
- Create: `go.mod`, `.gitignore`（`/out/`, `*.exe`, `/testdata/golden/.venv/`）, `internal/model/model.go`, `internal/model/version.go`
- Test: `internal/model/model_test.go`, `internal/model/version_test.go`
- 移植元: `models.py`, `plan.py`（`compare_versions` と `_semver_key` 〜 `_natural_key`）, `tests/test_versions.py`（compare 部分）, `tests/test_accuracy_core.py`（purl / ecosystem 部分）

**Interfaces:**
- Produces（`package model`）:
  - `type Severity string`（定数 `SeverityCritical`…`SeverityUnknown`）、`func ParseSeverity(s string) Severity`、`func SeverityRank(s Severity) int`（critical=4 … unknown=0。dedup.py `_SEV_ORDER` と同値）
  - `func NormalizeEcosystem(v string) string`、`func ParsePurl(p string) (typ, namespace, name, version string)`
  - `type Package struct{ Name, Version, Ecosystem, Purl, VersionSource, FixedVersion string; FixedVersionCandidates []string }`
  - `type Asset struct{ Identifier, Kind, Criticality string; InternetExposed, Reachable, RuntimeObserved *bool; SystemExposure, Automatable, MissionImpact, SafetyImpact, PubliclyExposed, BOD2604Applicability string; ContextSources []string; Owner, ContextNotes string }`、`func NewAsset(identifier string) Asset`（既定値 kind/criticality/各文脈 = "unknown"）、`func (a *Asset) Normalize() error`（Python validator と同一の正規化と許容値検証）
  - `RawFinding`, `VendorAdvisory`, `Enrichment`, `Finding`（フィールドは models.py と同名 snake_case JSON タグ。`RawFinding.Raw json.RawMessage \`json:"-"\``、`Finding.SSVCInputs map[string]string`、`Finding.Triage *Triage`）
  - `type DecisionPoint struct{ Key, Version, Value, Label, Confidence, Source string; Evidence []string; Inferred, NeedsConfirmation bool }`
  - `type SSVCAssessment`（ssvc.py `SSVCAssessment` と同フィールド。`TechnicalImpact *DecisionPoint`、`Supplemental map[string]any`）
  - `type BODInput struct{ Point, Value, Source, Basis string; Defaulted, Resolved bool }`、`type BODResult`（bod2604.evaluate の返す dict と同キー。`Outcome, OutcomeLabel, ProvisionalOutcome, ProvisionalLabel *string`、`DeadlineDays *int`、`Inputs map[string]BODInput`（JSON 出力順は in_kev, publicly_exposed, automatable, technical_impact — `MarshalJSON` で順序固定）
  - `type Effective struct{ SSVCOutcome string; SSVCWorkflowDays *int; BODOutcome *string; BODStatus string; Obligations []string; RequiresConfirmation bool; Rule string; DeadlineDays *int; DeadlineSource, Explanation string }`
  - `type Triage struct{ Priority, Action, Rationale string; SuggestedDeadlineDays int; Backend string; SSVC *SSVCAssessment; Audit map[string]any; BOD2604 *BODResult; Effective *Effective }`（JSON キー: priority, action, rationale, suggested_deadline_days, backend, ssvc, audit, bod2604, effective。audit/bod2604/effective は nil なら省略 — Python は未設定キーを持たないため）
  - `type Coverage = map[string]any`
  - `func CompareVersions(left, right, ecosystem string) int`（-1/0/1）

- [ ] **Step 1: ブランチ作成と go mod init**

Run: `git switch -c go-port-phase1 && go mod init github.com/d01ki/PatchTriage-go`
Expected: `go.mod` に `module github.com/d01ki/PatchTriage-go` と `go 1.27`。

- [ ] **Step 2: 失敗するテストを書く**

`model_test.go`:
- `TestNormalizeEcosystem` — 表: `"PyPI"→"pypi"`, `"python"→"pypi"`, `"GitHub Actions"→"githubactions"`, `"go"→"golang"`, `"java-archive"→"maven"`, `"jar"→"maven"`, `"unknown"→""`, `"apk"→"alpine"`。
- `TestParsePurl` — `pkg:npm/%40babel/core@7.0.0` → (`npm`,`@babel`,`core`,`7.0.0`)；`pkg:maven/org.springframework/spring-beans@5.3.17?type=jar` → (`maven`,`org.springframework`,`spring-beans`,`5.3.17`)；`pkg:npm/@scope/x`（@ 先頭は scope）→ version `""`；`not-a-purl` → 全部空。
- `TestParseSeverity` — `"Moderate"→medium`, `"important"→high`, `""→unknown`, `"bogus"→unknown`。
- `TestAssetNormalize` — `system_exposure:"Open"→"open"`、`mission_impact:"mef-failure"→"mef_failure"`、`system_exposure:"public"` はエラー（メッセージに `system_exposure must be one of:`）。
- `TestFindingJSONShape` — 空の `Finding{Key:"k",VulnID:"CVE-1",Package:{Name:"p"},Asset:NewAsset("a")}` を Marshal し、`"cvss_score":null`, `"aliases":[]`, `"triage":null`, `"internet_exposed":null` を含み `"raw"` を含まないこと。

`version_test.go`: `TestCompareVersions` — 移植元 `tests/test_versions.py` と `tests/test_remediation.py` 内の compare_versions ケースを全件移植し、加えて: semver `1.2.3 < 1.10.0`、`1.0.0-rc.1 < 1.0.0`；pypi `1.0.post1 > 1.0`、`2.0.0a1 < 2.0.0`；maven `5.3.18 > 5.3.17`、`1.0-SNAPSHOT < 1.0`；debian `2.36-9+deb12u3 > 2.36-9`、`1:1.0 > 2.0`、`1.0~rc1 < 1.0`。

- [ ] **Step 3: 失敗を確認**

Run: `go test ./internal/model/`
Expected: FAIL（undefined）

- [ ] **Step 4: model.go / version.go を実装**

models.py・plan.py の該当関数を忠実に移植。PEP 440 は `packaging.Version` の比較規則（epoch, release, pre/post/dev, local）を自前で実装し、パース不能時は natural key にフォールバック（plan.py `compare_versions` の分岐順をそのまま）。

- [ ] **Step 5: テスト成功を確認**

Run: `go test ./internal/model/ -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add go.mod .gitignore internal/model
git commit -m "feat(model): normalized data model and version ordering"
```

---

### Task 2: data 埋め込み + golden 生成

**Files:**
- Create: `data/data.go`, `data/*`（移植元 `src/patchtriage/data/` の demo_*.json, demo_assets.yaml, ssvc_validation.json, fixtures/*.json を**コピー**）, `testdata/`（移植元 `tests/fixtures/*` をコピー）, `testdata/golden/gen_golden.py`, `testdata/golden/*.json`

**Interfaces:**
- Produces（`package data`）: `var FS embed.FS`（`//go:embed *.json *.yaml fixtures/*.json`）、`func ReadFile(name string) ([]byte, error)`
- Produces（golden）: `testdata/golden/demo.json`, `trivy.json`, `grype.json`, `trivy_grype.json`（trivy+grype 同時投入）, `sbom_cyclonedx.json`, `sbom_spdx.json` — いずれも CLI `report.json` と同形（findings / actions / evaluation / response_policy / coverage）。SBOM 2 件は OSV 応答を `testdata/golden/osv_responses.json` に記録したものを Python 側で monkeypatch して生成（Go 側 Task 4 / 11 でも同じ応答を httptest で返す）。

- [ ] **Step 1: ファイルをコピー**（`cp` のみ。移植元を変更しない）

- [ ] **Step 2: `gen_golden.py` を書く**

挙動: 引数なし。`sys.path` は触らず、venv にインストールされた `patchtriage` を import。各ケースで `patchtriage.assess.assess(files, asset=..., snapshot=<demo_* 4 ファイル>, vendor_sources=None, use_vulnrichment=True)` を呼び、cli `_emit` と同じ dict を作って `json.dumps(indent=2, sort_keys=True, default=str)` で保存。demo ケースは `cli.demo` と同じ入力（`data/fixtures/trivy_sample.json` + `grype_sample.json` と `demo_assets.yaml`）。時刻系キー（`enriched_at`, `detected_at`, `first_seen`）は保存時に `"<time>"` へ置換。

- [ ] **Step 3: golden を生成**

```bash
python -m venv "$SCRATCH/pyvenv" && "$SCRATCH/pyvenv/Scripts/pip" install /c/Users/iniad/patchtriage
"$SCRATCH/pyvenv/Scripts/python" -I testdata/golden/gen_golden.py
cd /c/Users/iniad/patchtriage && git status --short   # 期待: 出力なし（移植元が無変更）
```
Expected: `testdata/golden/*.json` が 6 件、demo.json に CVE-2022-22965=immediate、CVE-2023-4911=out_of_cycle。

- [ ] **Step 4: `data.go` の埋め込みテスト**

`data/data_test.go` `TestEmbeddedFiles` — `ssvc_validation.json`, `demo_kev.json`, `demo_assets.yaml`, `fixtures/trivy_sample.json` が読めて空でない。Run: `go test ./data/` → PASS

- [ ] **Step 5: Commit**

```bash
git add data testdata
git commit -m "test: embed demo data and add Python-generated golden reports"
```

---

### Task 3: スキャナ取り込み（Trivy / Grype / OSV-Scanner）+ OSV 照合

**Files:**
- Create: `internal/ingest/scanner.go`, `internal/ingest/osv.go`（照合ロジック部分のみ。HTTP は Task 4）
- Test: `internal/ingest/scanner_test.go`, `internal/ingest/osv_test.go`
- 移植元: `ingest/parsers.py`、`tests/test_pipeline.py` / `tests/test_accuracy_core.py` / `tests/test_sbom.py` の parser・fixed 選択・affects 関連テスト

**Interfaces:**
- Consumes: Task 1 の model 型、`model.CompareVersions`
- Produces（`package ingest`）:
  - `type LoadResult struct{ Findings []model.RawFinding; Coverage model.Coverage }`
  - `func SniffFormat(data []byte) string`（"trivy" | "grype" | "osv" | ""）
  - `func ParseScanner(data []byte, format string, asset *model.Asset) ([]model.RawFinding, error)`
  - `func LoadFile(ctx context.Context, path, format string, asset *model.Asset, osv *OSVClient) (LoadResult, error)`（SBOM は Task 4 の `loadSBOM` へ委譲。Task 3 時点では SBOM 判定時に未実装エラー）
  - OSV 型: `type OSVVuln struct{ ID string; Aliases []string; Summary, Details string; Affected []OSVAffected; References []struct{URL string}; Severity []struct{Type, Score string} }`, `OSVAffected{ Package *OSVPackage; Versions []string; Ranges []OSVRange }`, `OSVRange{ Type string; Events []OSVEvent }`, `OSVEvent{ Introduced, Fixed, LastAffected, Limit *string }`
  - `func SelectOSVFixedVersion(v OSVVuln, pkg model.Package) string`、`func OSVAffects(v OSVVuln, pkg model.Package) bool`

- [ ] **Step 1: 失敗するテストを書く**

- `TestParseTrivySample` — `data/fixtures/trivy_sample.json` の件数・先頭 finding の vuln_id/パッケージ/fixed/severity/CVSS 最大値が Python と一致（期待値は golden の該当 finding から取る）。
- `TestParseGrypeTargetStringAndObject` — `source.target` が文字列 `"img:1"` / オブジェクト `{"userInput":"img:1"}` の両方で asset identifier=`img:1`。
- `TestParseGrypeRelatedCVEPreferred` — id `GHSA-xxxx`、related `CVE-2023-1` → vuln_id `CVE-2023-1`、aliases `[GHSA-xxxx]`。
- `TestSniffFormat` — Trivy / Grype / OSV / `{"results":[]}`→osv / `{}`→""。
- `TestLoadRejectsMalformedAndUnknown` — 壊れた JSON と `{"foo":1}` がエラー（後者のメッセージに `Unrecognized format`）、パニックしない。
- `TestLoadCRLFAndBOM` — UTF-8 BOM + CRLF の Trivy JSON が読める。
- `TestSelectOSVFixedVersion` — parsers.py docstring の各ケース: 不一致パッケージの entry を無視、qualified entry がある時は unqualified を無視、離散区間で installed を含む区間の fix を選ぶ、GIT range は versions 明示時のみ、明示 versions + 単一 fix へのフォールバック。移植元テストを全件移植。
- `TestOSVAffects` — introduced/fixed、last_affected（<=）、limit（<）、閉じない区間、version なしは true。

- [ ] **Step 2: 失敗を確認** — Run: `go test ./internal/ingest/` → FAIL

- [ ] **Step 3: 実装** — parsers.py を忠実に移植。入力用 struct は非公開型。BOM は `bytes.TrimPrefix` で除去。

- [ ] **Step 4: 成功を確認** — Run: `go test ./internal/ingest/ -v` → PASS

- [ ] **Step 5: Commit** — `git commit -m "feat(ingest): Trivy/Grype/OSV-Scanner parsing and OSV range matching"`

---

### Task 4: SBOM（CycloneDX / SPDX）+ OSV.dev クライアント

**Files:**
- Create: `internal/ingest/sbom.go`; Modify: `internal/ingest/osv.go`（クライアント追加）
- Test: `internal/ingest/sbom_test.go`
- 移植元: `ingest/sbom.py`（`versions.py` を使う `_resolve_versions` は**移植しない**：制約付き版は unqueryable として数える — 設計書 §10-3）、`tests/test_sbom.py`, `tests/test_coverage_messages.py`（取り込み側）

**Interfaces:**
- Produces:
  - `type OSVClient struct{ HTTP *http.Client; BaseURL string; CacheDir string }`、`func NewOSVClient(cacheDir string) *OSVClient`（BaseURL 既定 `https://api.osv.dev`、タイムアウト・バッチサイズ・並列は sbom.py の定数と同値、詳細キャッシュ 7 日）
  - `func IsSBOM(data []byte) string`（"cyclonedx" | "spdx" | ""）
  - `func ParseSBOMComponents(data []byte) ([]model.Package, error)`
  - `func loadSBOM(ctx context.Context, data []byte, asset *model.Asset, c *OSVClient) (LoadResult, error)` — coverage は `OsvCoverage.as_dict()` と同キー（`source_type:"sbom:osv"`, `complete`, `total_components` …, `inferred_components:0`, `inferred_versions:[]`）

- [ ] **Step 1: 失敗するテスト**
- `TestParseSBOMComponents` — `testdata/sbom_cyclonedx.json` / `sbom_spdx.json` の部品数・purl・version。
- `TestLoadSBOMAgainstRecordedOSV` — `httptest` が `testdata/golden/osv_responses.json` を返し、findings と coverage が golden `sbom_cyclonedx.json` の coverage と一致。
- `TestLoadSBOMConstraintVersionIsUnqueryable` — version `>=1.2` の部品は `unqueryable_components:1`、`unqueryable_names` に名前、`complete:false`。
- `TestLoadSBOMBatchFailureIsIncomplete` — querybatch が 500 → `failed_components>0`、`errors` 非空、`complete:false`、エラーで中断しない。
- `TestOSVCacheIsolation` — CacheDir を `t.TempDir()` にし、別ディレクトリのキャッシュを読まない。

- [ ] **Step 2〜4:** FAIL 確認 → sbom.py を移植 → `go test ./internal/ingest/ -v` PASS
- [ ] **Step 5: Commit** — `git commit -m "feat(ingest): CycloneDX/SPDX SBOM resolution through OSV.dev"`

---

### Task 5: dedup + inventory

**Files:**
- Create: `internal/ingest/dedup.go`, `internal/ingest/inventory.go`; Modify: `go.mod`（`gopkg.in/yaml.v3`）
- Test: `internal/ingest/dedup_test.go`, `internal/ingest/inventory_test.go`
- 移植元: `dedup.py`, `context.py`, `tests/test_accuracy_core.py`（dedup 部分）, `tests/test_config.py` は対象外

**Interfaces:**
- Produces:
  - `func PackageIdentity(p model.Package) (ecosystem, namespace, name, version string)`
  - `func Dedup(raw []model.RawFinding) []*model.Finding`（キー `vid|eco|ns|name|ver|asset`、ソートは severity→CVSS 降順。Python の安定ソート順を保つため `sort.SliceStable`）
  - `type InventoryEntry map[string]any`、`func LoadInventory(path string) ([]InventoryEntry, error)`、`func ApplyContext(findings []*model.Finding, inv []InventoryEntry) (int, error)`（glob は `path.Match`。Python `fnmatch` との差：`fnmatch` は大文字小文字を OS 依存にしない `fnmatchcase` か確認し同じ挙動にする）

- [ ] **Step 1: 失敗するテスト**
- `TestDedupMergesCVEAndGHSAAcrossScanners` — trivy `CVE-2023-1` + grype `GHSA-x`(related CVE-2023-1)、同 purl → 1 件、`reported_by:[grype,trivy]`、aliases `[GHSA-x]`、最大 severity / CVSS。
- `TestDedupKeepsDistinctVersionsAndAssets` — 同 CVE・異 version / 異 asset は別 finding。
- `TestDedupEmptyEcosystemDoesNotBridge` — ecosystem 空 + 2 つの異なる ecosystem 候補 → 統合しない。
- `TestDedupFixedCandidatesRetained` — 異なる fixed 値が `fixed_version_candidates` にソート済みで残る。
- `TestApplyContextGlob` — `demo_assets.yaml` 適用で一致数と `system_exposure` 等が設定され、不正値はエラー。
- `TestDedupMatchesGoldenTrivyGrype` — trivy+grype サンプルの dedup 結果キー集合が golden `trivy_grype.json` の findings[].key と一致。

- [ ] **Step 2〜4:** FAIL → 実装 → PASS
- [ ] **Step 5: Commit** — `git commit -m "feat(ingest): cross-scanner dedup and asset inventory context"`

---

### Task 6: SSVC Deployer（decision/ssvc.go）

**Files:**
- Create: `internal/decision/ssvc.go`
- Test: `internal/decision/ssvc_test.go`
- 移植元: `ssvc.py`, `triage/engine.py`（SSVCBackend のみ）, `tests/test_ssvc.py`, `tests/test_vulnrichment.py`（SSVC 側）, `tests/test_decision_quality.py`（判定部分）

**Interfaces:**
- Produces（`package decision`）:
  - 列挙型 `Exploitation`, `SystemExposure`, `Automatable`, `MissionImpact`, `SafetyImpact`, `HumanImpact`, `TechnicalImpact`, `Decision`（文字列型、値は ssvc.py と同一）
  - `func LabelFor(v string) string`
  - `func DeriveHumanImpact(m MissionImpact, s SafetyImpact) HumanImpact`
  - `func DeployerDecision(e Exploitation, x SystemExposure, a Automatable, h HumanImpact) Decision`
  - `func HumanImpactBranches(e, x, a string) []map[string]string`
  - `func Assess(f *model.Finding) model.SSVCAssessment`
  - `func Triage(f *model.Finding) *model.Triage`（= `triage_from_assessment(assess(f), "ssvc")`）
  - `func SortKey(f *model.Finding) [6]float64`、`func OrderLess(a, b *model.Finding) bool`（`ssvc_order_key` 昇順と等価）

- [ ] **Step 1: 失敗するテスト**
- `TestDeployerTableMatchesOfficial` — `data.ReadFile("ssvc_validation.json")` の deployer.rows 全 18 行 × 4 HI = 72 経路。
- `TestHumanImpactTableMatchesOfficial` — 同ファイルの human_impact 16 行。
- `TestExploitationPrecedence` — 表: KEV→active/high；KEV + 分析者 none → active かつ needs_confirmation、evidence に `cannot downgrade`；分析者 public_poc（KEV なし）→ inferred=false；Vulnrichment `poc`→public_poc；Vulnrichment `none` + exploit 参照 → public_poc + 要確認；参照のみ → public_poc/medium；検索済み参照なし → none/medium；未検索 → none/low + 要確認；`nvd_cvss_score` ありで `exploit_sources_checked` 空 → coverage `nvd-record`。
- `TestAutomatablePrecedence` — 分析者 > asset > Vulnrichment > CVSS `AU:N` > 既定 yes（要確認）。
- `TestExposureMissionSafetyDefaults` — 全 unknown → open / mef_support_crippled / marginal、全て needs_confirmation、confidence low；`internet_exposed:false` → controlled；criticality `critical` → mef_failure。
- `TestActionSelection` — fix なし & 非 defer → `mitigate`；scheduled & fix なし → `mitigate`（Python の分岐順: fix なし非 defer が先）；defer → `monitor`；immediate & fix → `patch_immediately`。
- `TestOrderLessIsOrdinal` — 同 priority 内で E→HI→EXP→A→EPSS→CVSS の順に比較されること（EPSS が高くても E が低ければ後ろ）。

- [ ] **Step 2〜4:** FAIL → ssvc.py を移植 → PASS
- [ ] **Step 5: Commit** — `git commit -m "feat(decision): CERT/CC SSVC Deployer ssvc:DT_DP:1.0.0"`

---

### Task 7: BOD 26-04（decision/bod2604.go）

**Files:**
- Create: `internal/decision/bod2604.go`
- Test: `internal/decision/bod2604_test.go`
- 移植元: `bod2604.py`, `tests/test_bod2604.py`（全件）, `testdata/bod2604_decision_table.json`

**Interfaces:**
- Consumes: Task 6 の `Assess` 結果（`model.SSVCAssessment`）
- Produces:
  - `const PolicyID = "cisa:DT_BOD2604:1.0.0"`、`var Sources map[string]any`（bod2604.SOURCES と同値）
  - `func BODOutcome(inKEV, publiclyExposed, automatable, technicalImpact string) string`
  - `func EvaluateBOD(f *model.Finding) model.BODResult`
  - `func ResolveEffective(ssvc *model.SSVCAssessment, p model.BODResult) model.Effective`
  - `func ApplyPolicy(findings []*model.Finding)`（Triage が nil の finding は飛ばす）
  - `type ActionPolicy struct{ BOD2604 map[string]any; EffectiveDeadlineDays *int; EffectiveRule string; Obligations []string }`、`func PolicyForAction(group []*model.Finding) (ActionPolicy, bool)`
  - `func SummarizePolicy(findings []*model.Finding) map[string]any`

- [ ] **Step 1: 失敗するテスト** — `tests/test_bod2604.py` の全テストを同名（Go の CamelCase）で移植。最低限: 16 行一致、applicability 4 値、KEV 取得失敗で in_kev unresolved、Vulnrichment 完了かつ非 KEV かつ両方未公開のときのみ CISA 既定（A=no, TI=total）、publicly_exposed は明示 no 以外で no にならない、5 つの effective rule、3DF の forensic_triage が短い期限でも保持、FSU を Defer/数値にしない。
- [ ] **Step 2〜4:** FAIL → 移植 → PASS
- [ ] **Step 5: Commit** — `git commit -m "feat(decision): CISA BOD 26-04 response policy cisa:DT_BOD2604:1.0.0"`

---

### Task 8: エンリッチメント（EPSS / KEV / NVD / Vulnrichment / キャッシュ / スナップショット）

**Files:**
- Create: `internal/enrich/enrich.go`
- Test: `internal/enrich/enrich_test.go`
- 移植元: `enrich/clients.py`, `tests/test_enrichment_clients.py`, `tests/test_vulnrichment.py`（取得側）, `tests/test_cache_isolation.py`

**Interfaces:**
- Produces（`package enrich`）:
  - `type Options struct{ UseNVD bool; NVDAPIKey string; VendorSources string /* "" = 無効, "auto", "all", またはカンマ区切り */; GitHubToken string; UseVulnrichment bool; CacheDir string; HTTP *http.Client; URLs Endpoints }`
  - `type Endpoints struct{ EPSS, KEV, NVD, CVERecord, MSRC, RHSA, UbuntuOSV, Debian, GHSA, ExploitDB string }`、`func DefaultEndpoints() Endpoints`（clients.py / vendors.py の URL 定数）
  - `func Enrich(ctx context.Context, findings []*model.Finding, o Options) error`
  - `type Snapshot struct{ EPSS, KEV, NVD, Vulnrichment json.RawMessage }`、`func DemoSnapshot() (Snapshot, error)`（data パッケージから）、`func EnrichFromSnapshot(findings []*model.Finding, s Snapshot) error`
  - `func ParseVulnrichmentSSVC(record json.RawMessage) map[string]string`
  - `func DefaultCacheDir() string`（`~/.cache/patchtriage/go`）

- [ ] **Step 1: 失敗するテスト**（すべて httptest。実ネットワーク禁止）
- `TestFetchEPSSBatches` / `TestFetchKEVSetsDatesAndRansomware` / `TestFetchNVDExploitReferences`（exploit-db / packetstorm ドメインのみ参照扱い）/ `TestParseVulnrichmentSSVC`（cisa-adp コンテナ以外を無視、不正値を無視）。
- `TestEnrichKEVFailureIsNotAbsence` — KEV が 500 → `in_cisa_kev:false` だが `retrieval_status["kev"]` が失敗を示し、BOD の in_kev が unresolved になる（Task 7 の EvaluateBOD を通して確認）。
- `TestEnrichRetriesOn429ThenRecords` — 429（Retry-After:0）→ 200 で成功；常に 429 → 上限回数で止まり `retrieval_errors` に記録、他ソースの結果は保持。
- `TestCacheIsolationAndStaleFallback` — CacheDir 分離；取得失敗時に古いキャッシュを使う場合は stale と記録し、空結果で上書きしない。
- `TestEnrichFromDemoSnapshotMatchesGolden` — demo の dedup 済み findings に `EnrichFromSnapshot` を適用し、各 finding の enrichment（時刻除く）が golden `demo.json` と一致。

- [ ] **Step 2〜4:** FAIL → 移植（並列数・タイムアウト・リトライ回数・キャッシュ寿命は clients.py の定数と同値）→ PASS
- [ ] **Step 5: Commit** — `git commit -m "feat(enrich): EPSS, CISA KEV, Vulnrichment and NVD evidence with cache"`

---

### Task 9: ベンダーアドバイザリ（MSRC / RHSA / USN / Debian / GHSA / Exploit-DB）

**Files:**
- Create: `internal/enrich/vendors.go`
- Test: `internal/enrich/vendors_test.go`
- 移植元: `enrich/vendors.py`, `tests/test_vendor_advisories.py`

**Interfaces:**
- Consumes: Task 8 の `Options`, `Endpoints`
- Produces: `func ParseSources(v string) ([]string, error)`、`func AutoSources(f *model.Finding) []string`、`func enrichVendors(ctx context.Context, findings []*model.Finding, o Options)`（`Enrich` から呼ぶ）、各 `parseMSRC/parseRHSA/parseUSN/parseDebian/parseGHSA/parseExploitDB(payload []byte, cve string) ([]model.VendorAdvisory, error)`

- [ ] **Step 1: 失敗するテスト** — `tests/test_vendor_advisories.py` を全件移植。加えて `TestMSRC404IsNoRecord`（エラーにしない）、`TestExploitDBNeverCached`（CacheDir にファイルが作られない）、`TestExploitDBExactCVEMatchOnly`、`TestExploitDBHitSetsPublicPoC`（Task 6 `Assess` で public_poc）、`TestExploitDBFailureIsNotCoverage`（`exploit_sources_checked` に入らない）。
- [ ] **Step 2〜4:** FAIL → 移植 → PASS
- [ ] **Step 5: Commit** — `git commit -m "feat(enrich): vendor advisory and Exploit-DB connectors"`

---

### Task 10: audit / plan / evaluate / presentation

**Files:**
- Create: `internal/pipeline/audit.go`, `plan.go`, `evaluate.go`, `presentation.go`
- Test: `internal/pipeline/pipeline_test.go`
- 移植元: `triage/audit.py`, `plan.py`（build_plan 部分）, `evalcmp.py`, `presentation.py`, `tests/test_decision_quality.py`, `tests/test_remediation.py`（plan 部分）

**Interfaces:**
- Consumes: Task 5 `PackageIdentity`、Task 6 `Triage`/`SortKey`/`OrderLess`、Task 7 `PolicyForAction`
- Produces（`package pipeline`）:
  - `type AuditSummary struct{ Total, Verified int; Flagged [][2]any }`、`func AuditFinding(f *model.Finding) map[string]any`、`func AuditAll(findings []*model.Finding) AuditSummary`（各 finding の `Triage.Audit` を設定）
  - `type Action`（plan.py `Action` と同フィールド・同 JSON キー。`BOD2604 map[string]any`、`EffectiveDeadlineDays *int`）、`func BuildPlan(findings []*model.Finding) []Action`
  - `type EvalRow`（evalcmp.py と同フィールド）、`func Evaluate(findings []*model.Finding) []EvalRow`
  - `func PriorityDefinition(p string) map[string]string`、`func DecisionQuality(findings []*model.Finding) map[string]any`、`func PriorityEvidence(f *model.Finding) []map[string]string`、`func PriorityBasis(f *model.Finding) string`、`func EvaluationOutcome(r EvalRow, total int) map[string]any`

- [ ] **Step 1: 失敗するテスト**
- `TestAuditVerifiesDeterministicTriage` — rules の Triage は verified。
- `TestAuditDetectsTamperedOutcome` — `Triage.Priority` を書き換えると `ssvc_consistency` フラグ。
- `TestBuildPlanGroupsAndRanks` — 同パッケージ 2 CVE → 1 action、target_version は候補の最大、id 形式 `upgrade:<asset>:<eco>:<ns>:<name>:<ver>`、fix なしは `mitigate` と summary 文言一致。
- `TestBuildPlanPreservesForensicObligation` — 3DF の finding を含む action の obligations に `forensic_triage`。
- `TestEvaluateTopK` — evalcmp の k 値と各カウント（移植元テストから）。
- `TestDecisionQuality` — test_decision_quality.py の期待値。

- [ ] **Step 2〜4:** FAIL → 移植 → PASS
- [ ] **Step 5: Commit** — `git commit -m "feat(pipeline): audit, remediation plan, ordering evaluation and presentation"`

---

### Task 11: パイプライン統括（assess）+ golden 一致

**Files:**
- Create: `internal/pipeline/assess.go`
- Test: `internal/pipeline/assess_test.go`
- 移植元: `assess.py`, `tests/test_assess.py`, `tests/test_coverage_messages.py`

**Interfaces:**
- Consumes: Task 3–10 の全て
- Produces:
  - `type Options struct{ Format string; Asset *model.Asset; Inventory string; SSVCOverrides map[string]map[string]string; DeclaredCoverage model.Coverage; ProviderStatus string; Snapshot *enrich.Snapshot; Enrich enrich.Options; OSV *ingest.OSVClient; Limit int; Progress func(string) }`
  - `type Assessment struct{ Findings, Subset []*model.Finding; Actions []Action; EvalRows []EvalRow; Coverage model.Coverage; Audit AuditSummary }`
  - `func Assess(ctx context.Context, files []string, o Options) (*Assessment, error)`（処理順は assess.py と同一: load → combine coverage → dedup → overrides(exploitation/automatable のみ) → inventory → enrich/snapshot → rules triage → `OrderLess` で並べ limit → audit → ApplyPolicy(全 findings) → plan → evaluate）
  - `func CombineCoverage(declared, observed model.Coverage, providerStatus string) model.Coverage`、`func MergeFileCoverage(c []model.Coverage) model.Coverage`、`func ResultMessage(findings []*model.Finding, actions []Action, incomplete bool, status string, coverage model.Coverage) string`
  - `func ReportJSON(a *Assessment) map[string]any`（cli `_emit` の dict と同キー: findings, actions, evaluation, response_policy, coverage）

- [ ] **Step 1: 失敗するテスト**
- `TestAssessMatchesGolden` — 表駆動で golden 6 件（SBOM 2 件は httptest OSV）。`ReportJSON` を JSON 化 → 時刻キーを `"<time>"` に置換 → `sort_keys` 相当で正規化して golden とバイト一致。差分時は最初の相違パスを表示するヘルパー `diffJSON(t, got, want)`。
- `TestAssessDemoOutcomes` — demo で CVE-2022-22965=immediate, CVE-2023-4911=out_of_cycle, CVE-2024-3094=scheduled, CVE-2021-23337=scheduled。
- `TestAssessLimitAppliesAfterSSVC` — limit=1 で低 CVSS の KEV finding が残る。
- `TestResultMessageStates` — test_coverage_messages.py の文言を全件移植。

- [ ] **Step 2〜4:** FAIL → 実装 → PASS（不一致はここで Task 1–10 に戻って修正。golden は変更しない）
- [ ] **Step 5: Commit** — `git commit -m "feat(pipeline): end-to-end assessment matching Python golden reports"`

---

### Task 12: レポート（JSON / HTML）+ CLI `run` / `demo`

**Files:**
- Create: `internal/report/report.go`, `internal/report/report.html.tmpl`, `cmd/patchtriage/main.go`
- Test: `internal/report/report_test.go`, `cmd/patchtriage/main_test.go`
- 移植元: `report/html.py`, `cli.py`（`run`, `demo`, `_emit`, `_print_*`）

**Interfaces:**
- Consumes: Task 11 `Assess`, `ReportJSON`
- Produces:
  - `type HTMLOptions struct{ Title string; Coverage model.Coverage; CoverageWarnings []string }`、`func RenderHTML(findings []*model.Finding, actions []pipeline.Action, rows []pipeline.EvalRow, o HTMLOptions) (string, error)`、`func WriteJSON(path string, a *pipeline.Assessment) error`
  - CLI: `patchtriage run FILES... [--format] [--assets] [--html] [-o] [--ssvc-exposure] [--ssvc-mission-impact] [--ssvc-safety-impact] [--ssvc-automatable] [--bod2604] [--publicly-exposed] [--no-nvd] [--no-vulnrichment] [--vendor-sources] [--no-vendor-advisories] [--limit]`（cli.py `run` と同名フラグ。`--triage` は `rules` 以外を「Go 版フェーズ1では未対応」で拒否）、`patchtriage demo [--html out/demo_report.html] [-o out/demo_report.json]`
  - `func run(args []string, stdout, stderr io.Writer) int`（テスト可能なエントリ）

- [ ] **Step 1: 失敗するテスト**
- `TestRenderHTMLSelfContained` — 出力に `<script src=` / `<link href="http` / `https://cdn` を含まない。
- `TestHTMLEscapesUntrustedText` — title/description に `<script>alert(1)</script>` → エスケープされて出力。
- `TestRenderHTMLDemoSections` — demo で Immediate 行に CVE-2022-22965、BOD セクション、Outcome check 表が存在（html.py の見出し文字列で確認）。
- `TestCLIDemoWritesReports` — `run([]string{"demo","--html",tmp+"/r.html","-o",tmp+"/r.json"})` が 0 を返し、r.json が golden demo と一致（時刻除く）。
- `TestCLIRunRejectsAITriage` — `--triage ai` で非 0 と説明文。

- [ ] **Step 2〜4:** FAIL → 実装 → PASS
- [ ] **Step 5: 手動確認** — `go run ./cmd/patchtriage demo` → `out/demo_report.html` をブラウザで開き、Python 版 `C:\Users\iniad\patchtriage\out\demo_report.html` と見た目・内容を比較。
- [ ] **Step 6: Commit** — `git commit -m "feat(cli): run and demo commands with JSON and self-contained HTML reports"`

---

### Task 13: verify（適合性・再現性検証）

**Files:**
- Create: `internal/validation/verify.go`; Modify: `cmd/patchtriage/main.go`（`verify [--repeats 25] [--output verification_report.json]`）
- Test: `internal/validation/verify_test.go`
- 移植元: `validation.py`, `tests/test_validation.py`

**Interfaces:**
- Produces: `func Run(repeats int) (map[string]any, error)`（キー構成は validation.py `run_validation` と同一。`engine_source` フィンガープリントは Go 埋め込みのソース一覧ではなく `decision` パッケージの判定表を正規化 JSON 化した SHA-256 とし、その旨を `manifest` に記載）、`func WriteReport(path string, repeats int) (map[string]any, error)`

- [ ] **Step 1: 失敗するテスト** — `TestVerifyAllChecksPass`（全 check が passed、72/16 件）、`TestVerifyFingerprintStable`（2 回実行で `input_fingerprint` と `decision_fingerprint` が同一）、`TestTamperCheckDetects`（validation.py の tamper ケース全件で検出）。
- [ ] **Step 2〜4:** FAIL → 移植 → PASS
- [ ] **Step 5: Commit** — `git commit -m "feat(validation): offline conformance and repeatability verify command"`

---

### Task 14: GUI ストア + ランナー（targets / summary / fleet 集約）

**Files:**
- Create: `internal/web/store.go`, `internal/web/runner.go`
- Test: `internal/web/store_test.go`, `internal/web/runner_test.go`
- 移植元: `targets.py`, `webapp/runner.py`, `fleet.py`（`aggregate_fleet` と `_queue_sort_key` のみ）, `tests/test_webapp.py` / `tests/test_web_enhancements.py` / `tests/test_fleet.py` の該当部分

**Interfaces:**
- Produces:
  - `type Store struct{ Root string }`（Root 既定は Python と同じ解決: `PATCHTRIAGE_CONFIG_DIR` → `~/.config/patchtriage`、配下 `targets/<workspace>`）
  - `type Target map[string]any`（targets.py の dict 形をそのまま保存する JSON。キー名を変えないため map とする）
  - `func (s *Store) Load(ws string) ([]Target, error)`, `Add(ws string, fields map[string]any) (Target, error)`, `Update(ws, id string, fields map[string]any) (Target, error)`, `UpdateInputs(ws, id string, overrides map[string]map[string]string) (Target, error)`, `Delete(ws, id string) (bool, error)`, `Get(ws, id string) (Target, error)`, `SaveSource(ws, id, content, format, name string) (Target, error)`, `SaveRunArtifacts(ws, id string, summary map[string]any, html string, revision int, sha string) error`, `LoadSummary(ws, id string) (map[string]any, error)`, `CurrentReport(ws, id string) (string, error)`, `Cleanup(maxAge time.Duration) (int, error)`、エラー `ErrStaleInput`, `ErrTargetLimit`, `ErrSourceQuota`
  - `func RunTarget(ctx context.Context, s *Store, ws string, t Target, backend string) (map[string]any, error)`（runner.py の summary と同キー）
  - `func DecisionPath(f *model.Finding) map[string]any`、`func AggregateFleet(s *Store, ws string) (map[string]any, error)`

- [ ] **Step 1: 失敗するテスト**
- `TestStoreInvalidatesOnChange` — context/source/ssvc-inputs 変更で summary と report が無効化、`input_revision` が増える。
- `TestStoreRejectsBadIDsAndQuota` — 不正 id 形式、ターゲット上限、ソース容量上限。
- `TestRunTargetDemoSummaryMatchesPython` — demo ターゲットの summary を Python `run_target` で生成した `testdata/golden/web_demo_summary.json`（Task 2 の gen_golden.py にケース追加して生成）と比較（`duration_ms`, `target_id`, `report_url`, 時刻を除く）。
- `TestRunTargetStaleRevisionNotSaved` — 実行中に revision が変わると成果物を保存しない。
- `TestAggregateFleetExcludesUnassessed`。

- [ ] **Step 2〜4:** FAIL → 移植 → PASS
- [ ] **Step 5: Commit** — `git commit -m "feat(web): target store, run summaries and fleet aggregation"`

---

### Task 15: GUI サーバー + `serve`

**Files:**
- Create: `internal/web/server.go`, `internal/web/page.html`; Modify: `cmd/patchtriage/main.go`（`serve [--host 127.0.0.1] [--port 8765] [--no-browser]`）
- Test: `internal/web/server_test.go`
- 移植元: `webapp/server.py`, `webapp/page.py`, `tests/test_webapp.py`, `tests/test_web_enhancements.py`

**Interfaces:**
- Consumes: Task 14 全て
- Produces: `func NewServer(s *Store) http.Handler`、`func Serve(ctx context.Context, host string, port int, openBrowser bool) error`

- [ ] **Step 1: page.html を抽出** — `page.py` の `_TEMPLATE` 文字列を一字一句コピー（raw string なのでエスケープ変換不要）。`INDEX_HTML` が置換しているプレースホルダを確認し、`server.go` で同じ置換（Human Impact 行列は `decision.DeriveHumanImpact`、ラベルは `decision.LabelFor` から生成）を行う。
- [ ] **Step 2: 失敗するテスト**（`httptest.NewServer`）
- `TestIndexServesPageWithMatrix` — `/` が 200、`text/html`、Human Impact 行列の JSON 16 キーを含む。
- `TestConfigAdvertisesPhase1` — `/api/config` の `backends==["rules"]`、`capabilities` に `fleet-import` / `github-repository-sbom` を含まない、`ui_schema_version==2`、`limits` キーが Python と同じ。
- `TestDemoRunFlow` — cookie 取得 → `POST /api/demo` → `POST /api/targets/{id}/run` → `/api/jobs/{job}` を完了までポーリング → `/api/summaries` に outcomes、`/report/{id}` が HTML。
- `TestServerRejectsOversizeAndForeignSession` — `PATCHTRIAGE_MAX_REQUEST_BYTES` 超過で 413；別 cookie から他人の target id → 404。
- `TestUnportedEndpointsReturn501` — `/api/targets/{id}/repository` と `/api/fleet/import` が 501 で `{"error":...}`。
- `TestSSVCInputsInvalidateSummary` — ssvc-inputs 更新後 `/api/summaries` から当該結果が消える。
- [ ] **Step 3〜4:** FAIL → server.py を移植（環境変数名・既定値・cookie 名 `patchtriage_session`・TTL 6h・ジョブ上限は同一）→ PASS
- [ ] **Step 5: ブラウザ確認** — `go run ./cmd/patchtriage serve` → http://127.0.0.1:8765 で: Open workspace → demo → Run → Decision path / Action queue / Evidence & policy / Review inputs → 入力変更して再実行 → Open full report → Download HTML。Import repository / Import organization ボタンがエラー通知を出すこと。Python 版 GUI と並べて表示差がないこと。
- [ ] **Step 6: 全体検証** — `go vet ./... && go test ./... && go run ./cmd/patchtriage verify --repeats 25 --output out/verification_report.json` がすべて成功。移植元で `git status --short` が空。
- [ ] **Step 7: Commit** — `git commit -m "feat(web): GUI server with Python-compatible API and serve command"`
