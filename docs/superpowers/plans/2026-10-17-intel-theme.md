# GUI テーマ刷新 実装計画

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `serve` の GUI を、B 案のインテリジェンス製品風ダークテーマに統一する。あわせて、デスクトップ表示のスクロール範囲を判定列全体に広げる。

**Architecture:** `page.html` の `<style id="console-theme">` ブロックを、CSS 変数トークンを使う新しいテーマブロックに置き換える。古いライトテーマのブロックはレイアウト用として残す。SVG（フロー図、1件ツリー）の直書きの色はクラスに移し、テーマ CSS で色を付ける。IBM Plex の woff2 は `go:embed` で同梱し、`/fonts/` から配信する。

**Tech Stack:** Go `net/http` + `embed`、素の HTML/CSS/JS（ビルド工程なし）、検証には Python Playwright を使う。

**Spec:** `docs/superpowers/specs/2026-10-17-intel-theme-design.md`

## Global Constraints

- トークン値（spec §3 の値をそのまま使う）: `--bg #060a13`, `--s1 #0b1222`, `--s2 #101a2f`, `--line #1b2740`, `--line2 #26344f`, `--ink #e4eaf6`, `--mut #8391ab`, `--dim #56637c`, `--acc #22d3ee`, `--acc2 #3b82f6`, `--glow 0 0 0 1px #22d3ee66, 0 0 20px #22d3ee33`
- 結果の色: `--c-immediate #ff5a5f`, `--c-outofcycle #ffb340`, `--c-scheduled #5b8cff`, `--c-defer #64748b`（変数名は既存のもの。`OUTCOME_COLOR` はこれらを参照し続ける）
- シアン（`--acc`）は「操作できるもの・選択状態」だけ、結果の色は「判定結果」だけに使う。
- 黒いドロップシャドウは使わない。発光（`--glow`）は、選択中のターゲットとフォーカスリングだけに使う。
- 書体: IBM Plex Sans 400/500/600（本文・見出し）、IBM Plex Mono 400/500（CVE 番号・ハッシュのみ）。外部 CDN には一切依存しない。
- HTML レポート、CLI、API、JS の状態管理は変えない。
- 角丸: パネル 8px、カード・入力欄 6px、バッジ 4–5px。

## Review Focus

1. **1000px 以下・700px 以下**: 既存のページ全体スクロールが維持されること。スクロール修正が `@media(min-width:1001px)` の外に漏れていないことを、Task 4 で 1000px のスクリーンショットを撮って確認する。
2. **sticky タブ**: 結果パネルの祖先要素に `overflow:hidden` があると貼り付きが効かない。Task 4 で、判定列をスクロールしたあとも `#tab-overview` が表示領域内にあることを Playwright で確認する。
3. **SSVC 入力レビューの `<select>` とダイアログのフォーム**: ダーク背景で `option` の文字が読めなくなりやすい。Task 2 のスクリーンショット対象に含める。
4. **フォントが届かない場合**: `/fonts/` が 404 になっても、システムフォントにフォールバックして文字が表示されること（`font-family` にフォールバックを書く）。Task 1 のテストで 200 応答を固定する。
5. **外部通信**: テーマのどこかに `fonts.googleapis.com` などの外部 URL が混入しないこと。Task 4 で、Playwright で 127.0.0.1 以外へのリクエストがゼロであることを確認する。

---

### Task 1: フォントの同梱と配信

**Files:**
- Create: `internal/web/fonts/IBMPlexSans-{Regular,Medium,SemiBold}.woff2`, `internal/web/fonts/IBMPlexMono-{Regular,Medium}.woff2`, `internal/web/fonts/OFL.txt`
- Create: `internal/web/fonts.go`
- Modify: `internal/web/server.go`（`get` の `switch` で `/fonts/` の前方一致を処理する）
- Test: `internal/web/server_test.go`

**Interfaces:**
- Produces: `GET /fonts/<name>.woff2` を `Content-Type: font/woff2` で返し、`Cache-Control: public, max-age=31536000, immutable` を付ける。存在しない名前と `..` を含むパスは 404。Task 2 の `@font-face` はこの URL を参照する。

- [ ] **Step 1: 失敗するテスト `TestFontsAreServedFromBinary` を書く**
  `/fonts/IBMPlexSans-Regular.woff2` が 200・`font/woff2`・本文の先頭4バイトが `wOF2` であること。`/fonts/nope.woff2` と `/fonts/../page.html` が 404 であること。
- [ ] **Step 2: テストを実行し、失敗することを確認する**
  `go test ./internal/web/ -run TestFontsAreServedFromBinary` → FAIL（404）
- [ ] **Step 3: フォントを取得する**
  npm の `@ibm/plex-sans` と `@ibm/plex-mono`（`npm pack` で取り出す）、または IBM/plex の GitHub リリースから、Latin サブセットの woff2 を入手する（`fonts/split/woff2/*-Latin1.woff2` 相当）。合計 250KB 以下に収める。`OFL.txt` も同梱する。
- [ ] **Step 4: `fonts.go` に `//go:embed fonts/*.woff2` の `embed.FS` と `serveFont(w http.ResponseWriter, name string) bool` を実装し、`server.go` の `get` から呼ぶ**
  名前は `path.Base` で正規化し、`embed.FS` に存在するものだけ返す。
- [ ] **Step 5: テストを実行し、成功することを確認する**
  `go test ./internal/web/` → PASS
- [ ] **Step 6: コミットする** `feat(web): serve embedded IBM Plex fonts`

### Task 2: テーマトークンと全体の面（ランディング、トップバー、KPI、サイドバー、ボタン、フォーム、ダイアログ、トースト）

**Files:**
- Modify: `internal/web/page.html`（226–420行目の `<style id="console-theme">` を丸ごと置き換える）

**Interfaces:**
- Consumes: Task 1 の `/fonts/*.woff2`
- Produces: `:root` の CSS 変数（Global Constraints の名前）。Task 3 と Task 4 はこれらの変数だけを参照し、色を直書きしない。

- [ ] **Step 1: 置き換え前の見た目を記録する**
  スクラッチパッドで `pt.exe serve --port 8799` を起動し（`PATCHTRIAGE_CONFIG_DIR` もスクラッチパッドにする）、ランディング、ワークスペース（デモ実行後）、ターゲット追加ダイアログを 1440px で撮影する。
- [ ] **Step 2: `console-theme` ブロックを新しいテーマに置き換える**
  `@font-face`（`font-display: swap`、フォールバックは `"Segoe UI", system-ui, sans-serif` と `ui-monospace, Consolas, monospace`）、`:root` トークン、`body` の背景と文字色を定義する。トップバーは `linear-gradient(180deg,#0a1120,#060a13)` に下線1本。主要ボタン（`.btn.primary`）は `linear-gradient(90deg,var(--acc2),var(--acc))` に白文字。それ以外のボタンは透明背景に `--line2` の枠線。`.target.selected` は `--acc` の枠線に `--glow`。入力欄と `select option` は `--s2`。ダイアログは `--s1` の背景に `--line` の枠線。フォーカスリングは `outline: 2px solid var(--acc)`。ランディングのヒーローとベンチマーク部分も同じトークンで塗り直す。旧ブロックにあったレスポンシブ用の上書き（`@media` 内のレイアウト指定）は、色以外のものを残す。
- [ ] **Step 3: 再撮影して確認する**
  Step 1 と同じ画面を撮り、色以外の配置が崩れていないこと、`select` の選択肢が読めることを目視で確認する。
- [ ] **Step 4: `go test ./internal/web/` を実行し、PASS を確認してからコミットする** `style(web): intelligence-style dark theme tokens and surfaces`

### Task 3: 結果パネル、タブ、表、フロー図、1件ツリー

**Files:**
- Modify: `internal/web/page.html`（`renderResult`、`overviewBlock`、`flowSvg`、`treeSvg` とテーマ CSS）

**Interfaces:**
- Consumes: Task 2 のトークン
- Produces: `.resulthead` の上端線を、`--top` 変数（最上位の結果の色）で描く。`renderResult` は `.result` 要素に `style="--top:var(--c-…)"` を付ける。

- [ ] **Step 1: 結果ヘッダーを実装する**
  `.result` に、`top_ssvc_decision` に対応する `--top` を付け、`.resulthead{border-top:2px solid var(--top)}` にする。結果がないときは `--line2`。バッジ（`.priority.<cls>`）は「結果の色の枠線と文字、背景はその色の 8% 程度」にする。
- [ ] **Step 2: Overview の先頭に結果ごとの件数帯を追加する**
  `overviewBlock` の先頭に `<div class="outcomestrip">` を置き、`OUTCOME_ORDER` の順に4マス並べる。各マスは `border-left:2px solid <結果の色>`、22px の件数と結果名を表示する。件数は `summary.outcomes` から取る。
- [ ] **Step 3: タブと表を整える**
  `.resulttab[aria-selected=true]` は `--ink` の文字に `--acc` の下線、`box-shadow:0 8px 14px -10px var(--acc)`。表の見出しは `--mut`、行の区切りは `--line`。`.overviewtable` の CVE ボタンは IBM Plex Mono で `--acc` 色にする。KEV タグは `#ff5a5f66` の枠線に `#ff8a8d` の文字。
- [ ] **Step 4: フロー図を C 案の配色にする**
  `flowSvg` の `<rect>` に直書きしている `style="fill:…"` をやめ、`data-outcome` 属性とクラスで色を付ける。中間の箱は `fill:var(--s1)`、枠線は `#2c3b5a`、件数 0 の箱は枠線 `--line` で文字 `#4a566d`。結果の箱は、枠線と文字がその結果の色で、塗りはその色の約 12%（`color-mix(in srgb, <色> 12%, transparent)`）。帯は結果の色で `fill-opacity:.3`、`mix-blend-mode:screen`。ホバーとフォーカスでは `.6`、フィルタで外れた帯（`.dim`）は `.08` にする。キャンバスの背景は `--bg`。
- [ ] **Step 5: 1件ツリー（`treeSvg`）の色を新しいトークンに合わせる**
  選ばれた経路の箱は `--acc` の枠線にし、塗りは `color-mix(in srgb, var(--acc) 14%, var(--s1))`。仮置き（assumed）の箱は `--c-outofcycle` の枠線にする。葉は結果の色のままにする。
- [ ] **Step 6: `go test ./internal/web/` を実行し、PASS を確認してからコミットする** `style(web): result panel, overview strip, flow and tree colors`

### Task 4: スクロール修正の確定と総合検証

**Files:**
- Modify: `internal/web/page.html`（作業ツリーにあるスクロール修正。`.resulttabs` の sticky 背景を `--s1` にそろえる）
- Create（スクラッチパッドのみ）: Playwright の検証スクリプト

- [ ] **Step 1: Playwright で検証する**
  デモを実行し、次をすべて確認する。
  - 1440px: `.decisionpane` の `scrollTop` を 600 にしたあとも、`#tab-overview` の矩形が `.decisionpane` の表示範囲内にある（sticky が効いている）。
  - 1000px / 390px: `document.documentElement.scrollWidth <= innerWidth`。ページ全体がスクロールする（`body` の `overflow` が `hidden` ではない）。
  - `page.on("request")` で、`127.0.0.1` 以外の URL へのリクエストが 0 件。
  - `pageerror` とコンソールエラーが 0 件。
  - フィルタ（箱と帯のクリック）、Clear filter、CVE から Decision path へのジャンプが動く。
  - 3つの幅で、ランディング、Overview、Decision path、Action queue、Review inputs、ターゲット追加ダイアログを撮影し、目視で確認する。
- [ ] **Step 2: コントラストを計算する**
  `--ink`、`--mut`、`--acc` と、4つの結果の色それぞれについて、`--s1` と `--bg` に対するコントラスト比を計算する。本文に使う色は 4.5:1 以上であること。満たさない色は、明度だけを上げて調整する。
- [ ] **Step 3: `go vet ./...` と `go test -count=1 ./...` を実行し、全 PASS を確認してからコミットする** `fix(web): scroll the whole decision column on desktop`
