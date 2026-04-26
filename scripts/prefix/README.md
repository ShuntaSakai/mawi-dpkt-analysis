# scripts/prefix/

`scripts/prefix/` は、aguri が抽出した prefix 候補を flow 特徴量で再評価し、prefix ごとの flow 抽出と比較分析につなげるディレクトリです。

## パイプライン

```text
aguri_candidates.csv + flow CSV
  ↓
evaluate_prefixes.py
  ↓
prefix_evaluation.csv
selected_prefixes.csv
  ↓
filter_flows_by_prefix.py
  ↓
results/flows/prefix/<dataset>/*.csv
  ↓
scripts/flow/summarize_flow_features.py
  ↓
results/features/prefix/<dataset>/*_features.json
  ↓
scripts/graph/plot_prefix_comparison.py
  ↓
results/comparison/<dataset>/
```

## スクリプト

### `evaluate_prefixes.py`

- 入力:
  - flow CSV
  - `aguri_candidates.csv`
  - `config/prefix_selection.yaml`
- 出力:
  - `prefix_evaluation.csv`
  - `selected_prefixes.csv`
- 役割:
  - aguri の候補を flow 特徴量で再評価します
  - flow 数、packet 数、byte 数、短命 flow 比率、小規模 flow 比率、SYN-only-like 比率などを用いて選定します
  - `scan_candidate` や `passes_filters` を付与して、候補の性質を保持します

### `filter_flows_by_prefix.py`

- 入力:
  - full flow CSV
  - `selected_prefixes.csv`
- 出力:
  - prefix ごとの flow CSV
  - `selected_prefix_flows.csv`（`--write-combined` 指定時）
- 役割:
  - 選定済み prefix に一致する flow を抽出します
  - 既定では prefix ごとに別 CSV を書き出します

### `../graph/plot_prefix_comparison.py`

- 入力:
  - 全体 `features.json`
  - prefix `features.json` を格納したディレクトリ
- 出力:
  - `comparison_summary.csv`
  - comparison plots
- 役割:
  - MAWI 全体と各 prefix を 1 対 1 で比較します
  - 分布比較と behavioral indicators 比較を作成します

## 研究上の注意

- scan 的な prefix は単純に捨てず、`scan_candidate` として保持します
- 短命 flow や RST の多さだけで攻撃と断定しません
- 解釈は「可能性がある」「示唆する」「整合的である」といった慎重な表現を前提にします
- aguri の結果は候補抽出であり、最終判断は flow 特徴量に基づいて行います

## 実行例

```bash
python scripts/prefix/evaluate_prefixes.py \
  --flows results/flows/all/http_traffic.csv \
  --aguri results/aguri/http_traffic/http_traffic.aguri_candidates.csv \
  --config config/prefix_selection.yaml

python scripts/prefix/filter_flows_by_prefix.py \
  --flows results/flows/all/http_traffic.csv \
  --selected results/prefix/http_traffic/selected_prefixes.csv

python scripts/flow/summarize_flow_features.py \
  --input results/flows/prefix/http_traffic/dst_192.168.75.136_32.csv

python scripts/graph/plot_prefix_comparison.py \
  --overall results/features/all/http_traffic_features.json \
  --prefix-dir results/features/prefix/http_traffic
```
