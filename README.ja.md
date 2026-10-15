# PatchTriage (Go)

[English](README.md) | 日本語

PatchTriage は、スキャナーの検出結果を「この環境でどのパッチをいつ適用するか」という
判断に変換するツールです。脆弱性スキャン結果や SBOM を取り込み、検出を重複排除し、
悪用状況とベンダー情報を付加したうえで、決定論的な
[CERT/CC SSVC Deployer モデル](https://certcc.github.io/SSVC/howto/deployer_tree/)
(`ssvc:DT_DP:1.0.0`) を適用します。

出力はアクションキューです。各項目には SSVC の 4 つの判定のいずれかが付きます:
**Immediate**、**Out-of-Cycle**、**Scheduled**、**Defer**。

このリポジトリは Python 版 PatchTriage 0.6.0 の Go 移植です。GUI、オフラインデモ用
データ、SSVC 検証テーブルをすべて埋め込んだ単一の静的バイナリになります。判定は
Python 版と一致します。Python 版が生成したゴールデンレポートをテストスイートで照合
しています。

> AI が SSVC の判定を決めることはなく、スコアを作り出すこともありません。任意の AI
> バックエンドは説明文を改善するだけです。AI 出力に含まれる判定・アクション・期限・
> 数値は決定論的な結果と照合され、食い違いがあれば明示されます。

## インストール

```bash
go install github.com/d01ki/PatchTriage-go/cmd/patchtriage@latest
# またはチェックアウトから
go build -o patchtriage ./cmd/patchtriage
```

Go 1.27 以降が必要です。バイナリ自体に実行時依存はありません。リポジトリのスキャンと
`remediate` では `git` を使い、インストールされていれば `osv-scanner` / `npm` /
`pnpm` / `uv` も使います。

## クイックスタート

```bash
patchtriage demo      # 完全オフライン。同梱の証拠データで demo_report.html / .json を生成
patchtriage serve     # GUI コンソール (http://127.0.0.1:8765)
patchtriage start     # 対話形式: いくつかの質問に答えるとパッチ計画を出力
patchtriage setup     # 任意: AI プロバイダー、API キー、既定バックエンドの設定
```

| コマンド | 用途 |
|---|---|
| `run FILES...` | Trivy / Grype / osv-scanner の JSON、または CycloneDX / SPDX SBOM から判定と JSON・HTML レポートを生成 |
| `demo` | 同梱の EPSS / KEV / NVD / Vulnrichment スナップショットによるオフラインデモ |
| `verify` | オフラインでの SSVC 適合性・再現性の検証 |
| `serve` | Web GUI (匿名の分離ワークスペース、ターゲット、アップロード、リポジトリ取り込み) |
| `start` | ファイルまたはリポジトリ URL に対する対話形式の実行。`remediate` への引き継ぎも可能 |
| `setup` | 初回設定ウィザード。キーはその場で検証し、本人のみ読める形で保存 |
| `fleet URL` | GitHub アカウントのリポジトリを取り込み、横断的な 1 つのキューを作成 |
| `remediate` | 確認済みのアップグレードを分離した Git クローンに 1 件適用し、レビュー可能なパッチを出力 |

各コマンドのフラグは `patchtriage <command> -h` で確認できます。

## スクリプトからの利用

```bash
# スキャナー出力から JSON と自己完結型 HTML レポートを生成
patchtriage run trivy.json grype.json --assets assets.yaml --html report.html -o report.json

# SBOM を OSV.dev で評価 (バージョン制約はパッケージレジストリで解決)
patchtriage run sbom.spdx.json --html report.html

# インベントリなしでターゲットの文脈を明示
patchtriage run trivy.json --ssvc-exposure open --ssvc-mission-impact mef_failure --ssvc-safety-impact critical

# CISA BOD 26-04 の入力 (別ポリシー。SSVC の結果は変わりません)
patchtriage run trivy.json --bod2604 voluntary --publicly-exposed yes

# 高速化: NVD を省略 (EPSS と CISA KEV は残る)、またはベンダーアドバイザリを省略
patchtriage run trivy.json --no-nvd
patchtriage run trivy.json --no-vendor-advisories
```

`assets.yaml` の例:

```yaml
assets:
  - match: "web-frontend*"
    system_exposure: open
    mission_impact: mef_failure
    safety_impact: critical
```

不明な入力には SSVC の保守的な既定値を使い、確認が必要な項目として明示します。
安全とみなすことはありません。

## Fleet

```bash
patchtriage fleet https://github.com/your-org --limit 10 \
  --ssvc-exposure controlled --html fleet_report.html -o fleet.json
```

各リポジトリはローカルストアのターゲットになり、Dependency Graph の SBOM が添付され
ます。クローンもコード実行も行いません。取り込み処理は GUI での単一リポジトリ取り込み
と同じコードです。ターゲットごとに評価し、結果を判定順に 1 つのキューへまとめます。
集約時に判定をやり直すことはありません。フォークとアーカイブ済みリポジトリは、指定
しない限りスキップします。レート制限やクォータに達した場合は、理由を表示して取り込み
を停止します。未評価のターゲットは一覧に表示しますが、すべての集計から除外します。

## 依存関係パッチの適用と検証

```bash
patchtriage run osv.json -o report.json
patchtriage remediate report.json --repository ./app --output-dir ./out/app-remediation --check "npm test"
patchtriage remediate            # 対話形式: 不足している入力をすべて質問
```

`remediate` はコミット済みの `HEAD` を出力ディレクトリにクローンし、依存関係の宣言を
編集します。対応ファイルは `package.json`、`requirements*.txt`、PEP 621 および Poetry
の `pyproject.toml` です。続いてライフサイクルスクリプトを無効にした状態で
`package-lock.json`、`pnpm-lock.yaml`、`uv.lock` を更新し、指定したチェックを実行します
(シェルを介さずに解釈します)。OSV-Scanner があれば最後に再スキャンします。出力
ディレクトリには `workspace/`、`remediation.patch`、`remediation.json` と変更後の
スキャン結果が入ります。`remediate` は元のチェックアウトを変更せず、push・マージ・
デプロイも行いません。

## 任意の AI による説明

```bash
export PATCHTRIAGE_AI_PROVIDER=anthropic ANTHROPIC_API_KEY=...
patchtriage run trivy.json --triage cascade --html report.html

export PATCHTRIAGE_AI_PROVIDER=ollama PATCHTRIAGE_AI_BASE_URL=http://localhost:11434/v1 PATCHTRIAGE_AI_MODEL=<model>
patchtriage run trivy.json --triage ai
```

| バックエンド | 動作 |
|---|---|
| `rules` | 決定論的な SSVC のみ。既定値で、CI に適しています。 |
| `ai` | 決定論的な結果に、プロバイダーが生成した説明を追加します。 |
| `cascade` | すべての検出を高速モデルで一次判定し、緊急・不確実・監査不合格のものを高精度モデルへ回します。 |

対応プロバイダーは `anthropic` (Messages、および `--batch` 指定時は Message Batches)、
`openai`、OpenAI 互換エンドポイント (`openai-compatible`、`ollama`) です。プロバイダー
を暗黙に切り替えることはありません。API 呼び出しが失敗した検出はルールの結果に
フォールバックし、`rules_fallback` タグが付きます。

## 設定

環境変数は `patchtriage setup` が書き出すファイル
(`~/.config/patchtriage-go/config.json`、パーミッション 0600) より常に優先されます。

| 変数 | 用途 |
|---|---|
| `PATCHTRIAGE_AI_PROVIDER`, `PATCHTRIAGE_AI_MODEL`, `PATCHTRIAGE_AI_SCREEN_MODEL`, `PATCHTRIAGE_AI_DEEP_MODEL`, `PATCHTRIAGE_AI_BASE_URL`, `PATCHTRIAGE_AI_API_KEY` | AI プロバイダーの選択 |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` | プロバイダーの認証情報 (プロバイダーごとに別管理) |
| `NVD_API_KEY` | NVD のレート制限を緩和 |
| `GITHUB_TOKEN` / `GH_TOKEN` | GitHub API の制限を緩和。ローカルモードではプライベートリポジトリにも使用 |
| `PATCHTRIAGE_CONFIG_DIR`, `PATCHTRIAGE_CACHE_DIR` | `~/.config/patchtriage-go` と `~/.cache/patchtriage-go` を上書き |
| `PATCHTRIAGE_DEPLOYMENT_MODE` | `local` (既定) または `public`。public モードでは取り込みにサーバーのトークンを使いません |
| `PATCHTRIAGE_ALLOW_GENERIC_REPOSITORIES` | GitHub 以外の HTTPS Git ホストに対するローカル OSV-Scanner 取り込みを有効化 |
| `PATCHTRIAGE_COOKIE_SECURE` | `auto` (`X-Forwarded-Proto` から判断)、`true`、`false` |
| `PATCHTRIAGE_MAX_*` | GUI の上限 (リクエスト・ソースのバイト数、ターゲット数、ジョブ数、fleet 取り込み件数) |

## Docker

```bash
docker compose up gui                       # GUI (http://localhost:8765)
docker compose run --rm demo                # オフラインデモ -> ./out/demo_report.html
docker compose run --rm start               # 対話形式の実行。このディレクトリが /work になります
docker compose run --rm triage run /work/sbom.json -o /out/report.json --html /out/report.html
```

イメージには `git`、`npm`、バージョン固定の `osv-scanner` が含まれ、非特権ユーザーで
動作します。ターゲット、証拠データ、キャッシュは名前付きボリュームに保存されます。
TLS の背後で公開運用する場合は、`PATCHTRIAGE_DEPLOYMENT_MODE=public`、
`PATCHTRIAGE_ALLOW_GENERIC_REPOSITORIES=false`、`PATCHTRIAGE_COOKIE_SECURE=true` を
設定してください。

## 再現性

```bash
patchtriage verify --repeats 100 --output verification_report.json
```

`verify` はオフラインで次の項目を確認します。

- SSVC Deployer の全 72 パス
- Human Impact の全 16 組み合わせ
- ターゲットの文脈がそのままエンジンに渡ること
- 不明な文脈が保守的に扱われること
- 同じ判定を繰り返すと同一のハッシュになること
- 固定したエンドツーエンドのパイプラインが同じ結果を出し続けること
- 判定・アクション・期限の改変が検出されること

実行間で `input_fingerprint` と `decision_fingerprint` を比較してください。

## 制限事項

- PatchTriage は脆弱性スキャナーの代わりではありません。結果が空でも、ターゲットが
  安全である証明にはなりません。未対応またはアクセスできない入力は
  `coverage_incomplete` として報告し、問題なしとは扱いません。
- SSVC の判定は、組織の文脈と最新の脅威情報が正確であることを前提とします。推定した
  入力には人によるレビューが必要です。
- 自動パッチの対象は、npm と Python の直接依存の宣言のみです。

## 開発

```bash
go vet ./...
go test ./...
```

テストはネットワークにアクセスしません。`testdata/golden/` と
`testdata/*_python.json` のファイルは Python 版が生成したものです
(`testdata/golden/gen_golden.py` を参照)。これらは判定の一致を確かめる基準なので、
再生成は必ず Python 版で行い、この Go エンジンでは生成しないでください。

## ライセンス

Python 版 PatchTriage と同じ Apache License 2.0 です。[LICENSE](LICENSE) を参照して
ください。
