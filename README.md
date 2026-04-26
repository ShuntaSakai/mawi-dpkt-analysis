# mawi-dpkt-analysis

## 使い始め方

- 全体像を先に把握する場合は [scripts/](./scripts/README.md) を読み、そこから各系統の README に進んでください。
- フロー解析から始める場合の入口は [scripts/flow/README.md](./scripts/flow/README.md) です。主要コマンドは `scripts/flow/pcap_to_flow.py`、`scripts/flow/summarize_flow_features.py`、`scripts/graph/plot_flow_features.py` です。
- prefix 分析から始める場合は [scripts/aguri/README.md](./scripts/aguri/README.md) と [scripts/prefix/README.md](./scripts/prefix/README.md) を順に読んでください。入口は `scripts/aguri/run_aguri.py`、`scripts/aguri/parse_agurim.py`、`scripts/prefix/evaluate_prefixes.py` です。
- 出力先の見方は [results/README.md](./results/README.md)、閾値設定は [config/README.md](./config/README.md) を参照してください。

## プロジェクト概要

`mawi-dpkt-analysis` は、MAWI の `pcap` / `pcap.gz` を対象に `dpkt` でフローを生成し、特徴量抽出・要約・可視化・prefix 比較分析を行う研究用リポジトリです。

単に処理を実行するのではなく、トラフィックの構造的特徴を把握し、MAWI 全体と特定 prefix の差を解釈可能な形で説明できることを目的としています。

## 研究目的

- フロー単位で TCP / UDP 通信を集約し、分布として通信の特徴を捉える
- `aguri3` / `agurim` で有意な prefix 候補を抽出する
- aguri の候補を flow 特徴量で再評価し、解釈しやすい prefix を選定する
- MAWI 全体と prefix ごとの通信特性を比較し、差の意味を説明できるようにする

## パイプライン概要

### 全体フロー解析

```text
pcap.gz
  ↓
scripts/flow/pcap_to_flow.py
  ↓
results/flows/all/<dataset_name>/flows.csv
  ↓
scripts/flow/summarize_flow_features.py
  ↓
results/features/all/<dataset_name>/features.json
  ↓
scripts/graph/plot_flow_features.py
  ↓
results/flow_plots/all/<dataset_name>/*.png
```

### prefix 分析

```text
pcap.gz
  ↓
scripts/aguri/run_aguri.py
  ↓
results/aguri/<dataset>/<dataset>.agurim.txt
  ↓
scripts/aguri/parse_agurim.py
  ↓
results/aguri/<dataset>/<dataset>.aguri_candidates.csv
  ↓
scripts/prefix/evaluate_prefixes.py
  ↓
results/prefix/<dataset>/prefix_evaluation.csv
  ↓
results/prefix/<dataset>/selected_prefixes.csv
  ↓
scripts/prefix/filter_flows_by_prefix.py
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

## ディレクトリ構成

- [config/](./config/README.md)  
  └ 設定ファイル

- [results/](./results/README.md)  
  └ 生成物

- [scripts/](./scripts/README.md)  
  ├ [aguri/](./scripts/aguri/README.md)  
  ├ [flow/](./scripts/flow/README.md)  
  ├ graph/  
  ├ pipeline/  
  └ [prefix/](./scripts/prefix/README.md)

- state/  
  └ 旧バッチ系の処理状態

詳細なスクリプト仕様、入出力、実行例は各ディレクトリ README を参照してください。
