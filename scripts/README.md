# scripts/

`scripts/` には、MAWI 解析パイプラインを構成する実行スクリプトを配置しています。

## 主な分類

### `flow/`

- `pcap` / `pcap.gz` から双方向 flow CSV を生成します
- flow CSV から特徴量を要約し、`features.json` を生成します
- 可視化は [graph/](./graph/) のスクリプトを利用します

### `aguri/`

- `aguri3` / `agurim` の実行をラップします
- `agurim` のテキスト出力を prefix 候補 CSV に変換します
- 抽出された候補は、そのまま採用せず [prefix/](./prefix/) で再評価します

### `prefix/`

- aguri が出した prefix 候補を flow 特徴量で再評価します
- 選定した prefix ごとに flow を抽出します
- MAWI 全体と prefix ごとの比較可視化につなげます

### `graph/`

- 現行パイプライン用の可視化スクリプト群です
- `plot_flow_features.py` は単独の flow 特徴量可視化、`plot_prefix_comparison.py` は全体 vs prefix 比較を担当します

### `pipeline/`

- 将来的な一括実行用ディレクトリです
- 現時点ではファイルは未配置です

## 補助的・旧系統

- `analyze_one.py`
  - パケット単位の統計を `results/json/` に出力する旧系統スクリプトです
- `download_one.py`
  - MAWI データを 1 ファイル取得する補助スクリプトです
- `run_batch.py`
  - `download_one.py` と `analyze_one.py` を使う旧バッチ処理系です

現行の主系統は `flow/`、`aguri/`、`prefix/`、`graph/` を組み合わせるフロー解析・prefix 分析パイプラインです。
