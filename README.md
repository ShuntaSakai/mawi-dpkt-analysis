# mawi-dpkt-analysis

`mawi-dpkt-analysis` は、MAWI の `pcap` / `pcap.gz` を対象に `dpkt` でフローを生成し、特徴量抽出・要約・可視化・prefix 比較分析を行う研究用リポジトリです。

本プロジェクトの目的は、単に処理を実行することではなく、トラフィックの構造的特徴を把握し、MAWI 全体と特定 prefix の差を解釈可能な形で説明できるようにすることです。

## プロジェクト概要

- フロー単位で TCP / UDP 通信を集約し、分布として特徴を捉える
- `aguri3` / `agurim` で有意な prefix 候補を抽出する
- aguri の候補を flow 特徴量で再評価し、prefix を選定する
- MAWI 全体と prefix ごとの通信特性を比較し、差の意味を解釈する

## パイプライン概要

### 全体フロー解析

```text
pcap.gz
  ↓
scripts/flow/pcap_to_flow.py
  ↓
results/flows/all/*.csv
  ↓
scripts/flow/summarize_flow_features.py
  ↓
results/features/all/*_features.json
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
