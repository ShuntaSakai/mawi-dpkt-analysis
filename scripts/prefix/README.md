# scripts/prefix/

`scripts/prefix/` は、aguri が抽出した prefix 候補を flow 特徴量で再評価し、prefix ごとの flow 抽出と比較分析につなげるディレクトリです。

## 使い方

### 実行順序

```text
1. results/flows/all/<dataset>/flows.csv を用意する
2. results/aguri/<dataset>/<dataset>.aguri_candidates.csv を用意する
3. evaluate_prefixes.py で候補を再評価する
4. filter_flows_by_prefix.py で prefix ごとの flow CSV を切り出す
5. scripts/flow/summarize_flow_features.py で各 prefix flow を要約する
6. scripts/graph/plot_prefix_comparison.py で全体 vs prefix を比較する
```

### `evaluate_prefixes.py`

- 必須オプション:
  - `--flows`: 全体 flow CSV
  - `--aguri`: `aguri_candidates.csv`
- 主な任意オプション:
  - `--config`: 既定は `config/prefix_selection.yaml`
    - 小さいサンプル PCAP では `config/prefix_selection.sample.yaml` を使うと最後まで疎通確認しやすくなります
  - `--out-dir`: 省略時は `results/prefix/<aguri_dataset_name>/`
- 既定の出力:
  - `prefix_evaluation.csv`
  - `selected_prefixes.csv`
- 次の参照先:
  - `selected_prefixes.csv` を `filter_flows_by_prefix.py --selected` に渡します

```bash
python scripts/prefix/evaluate_prefixes.py \
  --flows results/flows/all/http_traffic/flows.csv \
  --aguri results/aguri/http_traffic/http_traffic.aguri_candidates.csv
```

### `filter_flows_by_prefix.py`

- 必須オプション:
  - `--flows`: 全体 flow CSV
  - `--selected`: `selected_prefixes.csv`
- 主な任意オプション:
  - `--out-dir`: 省略時は `results/flows/prefix/<flow_dataset_name>/`
  - `--write-separate`: 既定で有効。prefix ごとに 1 ファイルずつ出力します
  - `--write-combined`: 既定で無効。有効時は `selected_prefix_flows.csv` も出力します
- 既定の出力:
  - `dst_<normalized_prefix>.csv`
  - `selected_prefix_flows.csv`（`--write-combined` 指定時）
- 次の参照先:
  - 出力された prefix flow CSV を `scripts/flow/summarize_flow_features.py --input` に渡します

```bash
python scripts/prefix/filter_flows_by_prefix.py \
  --flows results/flows/all/http_traffic/flows.csv \
  --selected results/prefix/http_traffic/selected_prefixes.csv \
  --write-combined
```

### `scripts/graph/plot_prefix_comparison.py`

- 必須オプション:
  - `--overall`: 全体 `features.json`
  - `--prefix-dir`: prefix ごとの `*_features.json` を格納したディレクトリ
- 主な任意オプション:
  - `--out-dir`: 省略時は `results/comparison/<dataset_name>/`
    - `dataset_name` は `--overall` の JSON 内 `scope.dataset_name` を優先して決まります
- 既定の出力:
  - `comparison_summary.csv`
  - `plots/`
- 参照元:
  - prefix 側の `features.json` は通常 `scripts/flow/summarize_flow_features.py` で生成します

```bash
python scripts/graph/plot_prefix_comparison.py \
  --overall results/features/all/http_traffic/features.json \
  --prefix-dir results/features/prefix/http_traffic
```

## パイプライン詳細

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

## スクリプト詳細

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
  - flow CSV 側で宛先 prefix に一致しない候補も `prefix_evaluation.csv` に残し、`match_status` で確認できるようにします
  - `normalized_dst_prefix` 列を含む出力を作り、後段の抽出処理につなげます

### `filter_flows_by_prefix.py`

- 入力:
  - full flow CSV
  - `selected_prefixes.csv`
- 出力:
  - prefix ごとの flow CSV
  - `selected_prefix_flows.csv`（`--write-combined` 指定時）
- 役割:
  - `selected_prefixes.csv` の `normalized_dst_prefix` に一致する宛先 IP を抽出します
  - 既定では prefix ごとに別 CSV を書き出します
  - 結合出力では `matched_prefix`、`aggregate_id`、`prefix_score`、`scan_candidate`、`passes_filters` を付加します

### `scripts/graph/plot_prefix_comparison.py`

- 入力:
  - 全体 `features.json`
  - prefix `features.json` を格納したディレクトリ
- 出力:
  - `comparison_summary.csv`
  - `plots/` 配下の比較画像
- 役割:
  - MAWI 全体と各 prefix を 1 対 1 で比較します
  - `flow_inter_arrival_time`、`duration`、`packet_count`、`byte_count`、`avg_packet_size` の分布要約を比較します
  - behavioral indicators と TCP/UDP 比率も比較対象に含めます

## 研究上の注意

- scan 的な prefix は単純に捨てず、`scan_candidate` として保持します
- 短命 flow や RST の多さだけで攻撃と断定しません
- 解釈は「可能性がある」「示唆する」「整合的である」といった慎重な表現を前提にします
- aguri の結果は候補抽出であり、最終判断は flow 特徴量に基づいて行います
- 全体との差が見えても、フロー数が少ない prefix では解釈を強めすぎないようにします
