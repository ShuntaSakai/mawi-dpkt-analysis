# results/

`results/` には解析の中間成果物と可視化結果を保存します。

## 使い方

### どこを見ればよいか

- 全体フロー抽出の直後:
  - `results/flows/all/`
- aguri 候補抽出の直後:
  - `results/aguri/<dataset>/`
- prefix 評価の直後:
  - `results/prefix/<dataset>/`
- prefix flow 抽出の直後:
  - `results/flows/prefix/<dataset>/`
- flow 要約の直後:
  - `results/features/all/`
  - `results/features/prefix/`
- 単独可視化の直後:
  - `results/flow_plots/all/<dataset>/`
  - `results/flow_plots/prefix/`
- 全体 vs prefix 比較の直後:
  - `results/comparison/<dataset>/`

### 実行順序と参照先

```text
pcap.gz
  ↓
results/flows/all/<dataset>.csv
  ↓
results/features/all/<dataset>_features.json
  ↓
results/flow_plots/all/<dataset>/

pcap.gz
  ↓
results/aguri/<dataset>/
  ↓
results/prefix/<dataset>/selected_prefixes.csv
  ↓
results/flows/prefix/<dataset>/ または results/flows/prefix/<flow_dataset_name>/
  ↓
results/features/prefix/
  ↓
results/comparison/<dataset>/
```

### 既定出力先の見方

- `scripts/prefix/evaluate_prefixes.py`
  - 省略時は `results/prefix/<aguri_dataset_name>/`
- `scripts/prefix/filter_flows_by_prefix.py`
  - 省略時は `results/flows/prefix/<flow_dataset_name>/`
- `scripts/flow/summarize_flow_features.py`
  - 入力が `results/flows/prefix/...` 配下なら `results/features/prefix/...`
  - それ以外は `results/features/all/`
- `scripts/graph/plot_prefix_comparison.py`
  - 省略時は `results/comparison/<dataset_name>/`

## ディレクトリ詳細

### `flows/`

- `results/flows/all/`
  - 全体 flow CSV を保存します
  - 現在は `http_traffic.csv` があります
- `results/flows/prefix/`
  - prefix ごとの flow CSV を保存します
  - `filter_flows_by_prefix.py` は通常 `results/flows/prefix/<flow_dataset_name>/` を作成します
  - 既存データに `results/flows/prefix/dst_192.168.75.136_32.csv` のような直下配置がある場合は、旧出力や手動整理の可能性があります

### `aguri/`

- `results/aguri/<dataset>/`
  - `aguri3` / `agurim` の出力を保存します
  - 主なファイル:
    - `<dataset>.agr`
    - `<dataset>.agurim.txt`
    - `<dataset>.aguri_candidates.csv`

### `prefix/`

- `results/prefix/<dataset>/`
  - prefix 評価結果を保存します
  - 主なファイル:
    - `prefix_evaluation.csv`
    - `selected_prefixes.csv`
- 例:
  - `results/prefix/http_traffic/`
  - `results/prefix/http_traffic_low/`

### `features/`

- `results/features/all/`
  - 全体 `features.json` を保存します
  - 現在は `http_traffic_features.json` があります
- `results/features/prefix/`
  - prefix ごとの `features.json` を保存します
  - `summarize_flow_features.py` の既定動作では、入力の相対パスに応じてサブディレクトリが作られることがあります
  - 既存データに `results/features/prefix/dst_192.168.75.136_32_features.json` のような直下配置がある場合は、その時点の運用に合わせた出力です

### `flow_plots/`

- `results/flow_plots/all/`
  - 全体 flow の単独可視化を保存します
  - 現在は `results/flow_plots/all/http_traffic/` があります
- `results/flow_plots/prefix/`
  - prefix flow を同様に可視化する際の出力先です

### `comparison/`

- `results/comparison/<dataset>/`
  - 全体 vs prefix の比較結果を保存します
  - 主なファイル:
    - `comparison_summary.csv`
    - `plots/`
- 現在は `results/comparison/http_traffic/` があります

## 旧系統

- `results/json/`
  - `scripts/analyze_one.py` が出力する旧系統のパケット統計 JSON です
- `results/plots/`
  - `scripts/analyze_one.py` / `scripts/run_batch.py` 系で使う旧系統の可視化出力先です

現行の主系統は `results/flows/`、`results/features/`、`results/flow_plots/`、`results/aguri/`、`results/prefix/`、`results/comparison/` です。
