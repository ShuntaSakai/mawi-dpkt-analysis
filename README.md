# mawi-dpkt-analysis

MAWI の `pcap.gz` を対象に、`dpkt` を使ってフロー単位の特徴量抽出、要約、可視化、比較へつなげるためのプロジェクト。

現状の主軸は、次のフロー解析パイプラインです。

```text
pcap.gz
  ↓
scripts/flow/pcap_to_flow.py
  ↓
flow CSV
  ↓
scripts/flow/summarize_flow_features.py
  ↓
features.json
  ↓
scripts/flow/plot_flow_features.py
  ↓
PNG 可視化
```

このパイプラインの目的は、通信の性質を個々のパケットではなく「フロー分布」として説明できるようにすることです。特に、MAWI 全体と特定 prefix の通信を比較し、短命フロー、偏った方向性、スキャン的挙動、支配的フローの違いを説明するための基盤として設計しています。

## セットアップ

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

主な依存ライブラリ:

- `dpkt`: pcap / pcapng 解析
- `matplotlib`: グラフ生成
- `PyYAML`: 設定ファイル利用時の YAML 読み込み

Matplotlib がキャッシュディレクトリへ書き込めない環境では、必要に応じて `MPLCONFIGDIR` を設定してください。

```bash
export MPLCONFIGDIR=/tmp/mplconfig
```

## フロー解析パイプライン

### 1. `scripts/flow/pcap_to_flow.py`

目的:

- パケット列を双方向フローへ集約する

処理内容:

- Ethernet フレームを順に読む
- IPv4 / IPv6 のみ対象にする
- TCP / UDP のみ対象にする
- 5 タプルをもとに双方向フローとして集約する

フロー定義:

- `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`
- A->B と B->A は同一フローに正規化する
- 最初に観測した方向を `src` / `dst` として保持する
- タイムアウト分割は行わず、1 本の入力ファイル内で一貫して集約する

出力 CSV の主な列:

- `start_time`, `end_time`, `duration`
- `packet_count`, `byte_count`, `pps`, `bps`
- `packets_from_src`, `packets_from_dst`
- `bytes_from_src`, `bytes_from_dst`
- `syn_count`, `syn_ack_count`, `ack_count`, `fin_count`, `rst_count`

実行例:

```bash
python scripts/flow/pcap_to_flow.py --input data/raw/202604080000.pcap.gz
```

デフォルト出力:

- `results/flows/<input_name>.csv`

例:

- 入力: `data/raw/202604080000.pcap.gz`
- 出力: `results/flows/202604080000.csv`

### 2. `scripts/flow/summarize_flow_features.py`

目的:

- flow CSV から研究用の `features.json` を生成する

特徴:

- 厳格パースで壊れた行を静かに混ぜない
- `invalid_rows` を JSON に残す
- `meta`, `scope`, `totals` を含む再現可能な構造
- 線形ヒストグラムと log ヒストグラムの両方を保存する

抽出している特徴量:

基本特徴量:

- `duration`
- `packet_count`
- `byte_count`
- `pps`
- `bps`
- `avg_packet_size`

分布特徴量:

- `flow_inter_arrival_time`

方向性特徴量:

- `packets_from_src_ratio`
- `bytes_from_src_ratio`

TCP 挙動特徴量:

- `syn_count`
- `syn_ack_count`
- `ack_count`
- `fin_count`
- `rst_count`

追加の要約:

- `tcp_flag_totals`
- `tcp_flag_rates_per_flow`
- `behavioral_indicators`
- `protocol_summary`
- `top.by_packet_count`
- `top.by_byte_count`
- `top.by_duration`
- `top.by_pps`
- `top.by_bps`

`behavioral_indicators` の意味:

- `short_flow_ratio_le_1s`: 短命フロー割合
- `tiny_flow_ratio_le_3packets`: 小規模フロー割合
- `rst_observed_flow_ratio`: RST を含むフロー割合
- `syn_only_like_flow_ratio`: スキャン的フロー割合

研究的な位置づけ:

- `duration`, `packet_count`, `byte_count`: フロー規模と継続時間の把握
- `pps`, `bps`: burst 性や高頻度フローの把握
- `avg_packet_size`: ACK 主体かデータ主体かの推定
- `flow_inter_arrival_time`: 連続発生やスキャン的短間隔の把握
- `*_from_src_ratio`: 通信の非対称性の把握
- `behavioral_indicators`: 異常寄りの振る舞いの直接的な指標

実行例:

```bash
python scripts/flow/summarize_flow_features.py --input results/flows/202604080000.csv
```

デフォルト出力:

- `results/features/<input_stem>_features.json`

例:

- 入力: `results/flows/http_traffic.csv`
- 出力: `results/features/http_traffic_features.json`

### 3. `scripts/flow/plot_flow_features.py`

目的:

- `features.json` から PNG を生成する

特徴:

- CSV を再読込せず、JSON のみで完結する
- JSON の `histogram` / `log_histogram` をそのまま使う
- `dataset_name` と `valid_flow_count` を図タイトルへ表示する
- `n < 30` のときは small sample 注記を入れる
- `protocol_flow_ratio` と `tcp_flag_rates_per_flow` も可視化する

生成される主なグラフ:

分布グラフ:

- `<feature>_hist.png`
- `<feature>_log_hist.png` (`log_scale_recommended` な特徴量のみ)

対象の主な特徴量:

- `duration`
- `packet_count`
- `byte_count`
- `pps`
- `bps`
- `avg_packet_size`
- `flow_inter_arrival_time`
- `packets_from_src_ratio`
- `bytes_from_src_ratio`

補助グラフ:

- `tcp_flag_totals.png`
- `tcp_flag_rates_per_flow.png`
- `behavioral_indicators.png`
- `protocol_flow_counts.png`
- `protocol_flow_ratios.png`
- `top_flows_by_packet_count.png`
- `top_flows_by_byte_count.png`
- `top_flows_by_duration.png`
- `top_flows_by_pps.png`
- `top_flows_by_bps.png`

グラフの意味:

- 分布グラフ: 個々のフローではなく、フロー集合の形を見る
- log ヒストグラム: 小さい値から大きい値までを同時に観察する
- 方向比率: 通信の非対称性を確認する
- TCP フラグ: 接続状態や異常終了の傾向を見る
- behavioral indicators: 短命通信、スキャン的挙動、異常傾向を見る
- protocol ratios: MAWI 全体と prefix の構成比比較に使う
- Top フロー: 外れ値や支配的通信を調べる

実行例:

```bash
python scripts/flow/plot_flow_features.py --input results/features/202604080000_features.json
```

デフォルト出力:

- ベースディレクトリ: `results/flow_plots`
- 実際の出力先: `results/flow_plots/<scope.dataset_name>/`

例:

- 入力: `results/features/http_traffic_features.json`
- `scope.dataset_name = "http_traffic"`
- 出力先: `results/flow_plots/http_traffic/`

## 典型的な実行手順

### 1 本の pcap.gz から flow CSV を作る

```bash
python scripts/flow/pcap_to_flow.py \
  --input data/raw/202604080000.pcap.gz
```

### flow CSV から features.json を作る

```bash
python scripts/flow/summarize_flow_features.py \
  --input results/flows/202604080000.csv
```

### features.json から PNG を作る

```bash
python scripts/flow/plot_flow_features.py \
  --input results/features/202604080000_features.json
```

## 研究上の見方

本プロジェクトで重要なのは、通信を単発の事例ではなく分布として説明することです。

見るべきポイント:

- `duration`: 短命フローが多いか、長時間継続フローがあるか
- `packet_count`, `byte_count`: mice / elephant の偏りがあるか
- `pps`, `bps`: 高頻度フローや burst 的挙動があるか
- `avg_packet_size`: 小さな制御中心か、データ転送中心か
- `flow_inter_arrival_time`: 短間隔で連発する挙動があるか
- `packets_from_src_ratio`, `bytes_from_src_ratio`: 片方向性が強いか
- `behavioral_indicators`: スキャン的・異常寄りの傾向が強いか
- `protocol_flow_ratios`: 全体と比べて TCP / UDP 構成比が偏っているか

比較研究の前提:

- 単体可視化は「その dataset の特徴把握」に使う
- MAWI 全体と prefix の比較は、別途比較専用スクリプトで行うのが望ましい
- 比較時は絶対件数だけでなく ratio を重視する

## 入出力の場所

主な入出力は次のとおりです。

### 入力

- `data/raw/`: 元の `pcap.gz`
- `results/flows/`: `pcap_to_flow.py` が生成した flow CSV
- `results/features/`: `summarize_flow_features.py` が生成した `features.json`

### 出力

- `results/flows/`: flow CSV
- `results/features/`: 特徴量要約 JSON
- `results/flow_plots/<dataset_name>/`: 可視化 PNG

既存の補助出力:

- `results/json/`: `scripts/analyze_one.py` のパケット統計 JSON
- `results/plots/`: `scripts/graph/plot_from_json.py` の旧可視化

## ディレクトリ

- `scripts/flow/pcap_to_flow.py`: pcap / pcapng から双方向 flow CSV を生成
- `scripts/flow/summarize_flow_features.py`: flow CSV から研究用 `features.json` を生成
- `scripts/flow/plot_flow_features.py`: `features.json` から PNG を生成
- `scripts/download_one.py`: MAWI の pcap.gz を 1 本取得
- `scripts/analyze_one.py`: パケット統計中心の旧 JSON 生成スクリプト
- `scripts/graph/plot_from_json.py`: 旧 JSON から PNG を生成するスクリプト
- `data/raw/`: ダウンロードした pcap.gz
- `results/flows/`: flow CSV
- `results/features/`: features JSON
- `results/flow_plots/`: flow 特徴量可視化
- `results/json/`: 旧パケット統計 JSON
- `results/plots/`: 旧パケット統計グラフ
- `state/`: 処理状態管理用ファイル
- `config/`: 設定ファイル用ディレクトリ

## 既存の補助スクリプト

初期段階で作成したパケット統計中心の系統も残しています。

### `scripts/download_one.py`

MAWI の `pcap.gz` を 1 本ダウンロードする。

```bash
python scripts/download_one.py
```

### `scripts/analyze_one.py`

`pcap.gz` を直接読み、パケットレベル統計を `results/json/` へ出力する。

```bash
python scripts/analyze_one.py
```

### `scripts/graph/plot_from_json.py`

`results/json/*.json` から旧来のグラフを生成する。

```bash
python scripts/graph/plot_from_json.py --input results/json/202604080000.json
```

これらはフロー解析パイプラインとは別系統ですが、初期の観察や補助的な確認には使えます。

## 方針

- `pcap.gz` は原則として展開せず、そのまま逐次読み込みする
- 巨大な入力データや生成物は Git 管理しない
- 相対パスの入出力はリポジトリルート基準で扱う
- フロー解析を主軸にし、比較研究へ拡張しやすい JSON 設計を維持する
- 単体可視化と比較可視化は責務を分ける
