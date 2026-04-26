# scripts/

## どこから読むか

- フロー解析から始める場合は [flow/README.md](./flow/README.md) を先に読んでください。
- prefix 分析を行う場合は [aguri/README.md](./aguri/README.md) を読んだ後に [prefix/README.md](./prefix/README.md) を読んでください。
- 出力画像の生成方法を確認したい場合は、各 README の実行例に加えて `graph/` のスクリプト名を参照してください。

## 主要コマンドの入口

- フロー生成: `scripts/flow/pcap_to_flow.py`
- フロー特徴量要約: `scripts/flow/summarize_flow_features.py`
- aguri 実行: `scripts/aguri/run_aguri.py`
- aguri 出力パース: `scripts/aguri/parse_agurim.py`
- prefix 再評価: `scripts/prefix/evaluate_prefixes.py`
- prefix flow 抽出: `scripts/prefix/filter_flows_by_prefix.py`
- 単独可視化: `scripts/graph/plot_flow_features.py`
- 全体 vs prefix 比較可視化: `scripts/graph/plot_prefix_comparison.py`

## 全体像

`scripts/` には、MAWI 解析パイプラインを構成する実行スクリプトを配置しています。現行の主系統は `flow/`、`aguri/`、`prefix/`、`graph/` を組み合わせるフロー解析・prefix 分析パイプラインです。

## ディレクトリ説明

### `flow/`

- `pcap` / `pcap.gz` から双方向 flow CSV を生成します
- flow CSV から特徴量を要約し、`features.json` を生成します
- 詳細は [flow/README.md](./flow/README.md) を参照してください

### `aguri/`

- `aguri3` / `agurim` の実行をラップします
- `agurim` のテキスト出力を prefix 候補 CSV に変換します
- 抽出された候補は、そのまま採用せず `prefix/` で再評価します
- 詳細は [aguri/README.md](./aguri/README.md) を参照してください

### `prefix/`

- aguri が出した prefix 候補を flow 特徴量で再評価します
- 選定した prefix ごとに flow を抽出します
- MAWI 全体と prefix ごとの比較可視化につなげます
- 詳細は [prefix/README.md](./prefix/README.md) を参照してください

### `graph/`

- 現行パイプライン用の可視化スクリプト群です
- `plot_flow_features.py` は単独の flow 特徴量可視化を担当します
- `plot_prefix_comparison.py` は MAWI 全体と prefix の 1 対 1 比較を担当します

### `pipeline/`

- 一括実行用のディレクトリです
- 現時点ではファイルは未配置です

## 補助的・旧系統

- `analyze_one.py`: パケット単位の統計を `results/json/` に出力する旧系統スクリプトです
- `download_one.py`: MAWI データを 1 ファイル取得する補助スクリプトです
- `run_batch.py`: `download_one.py` と `analyze_one.py` を使う旧バッチ処理系です
