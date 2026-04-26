# scripts/flow/

`scripts/flow/` は、pcap 系キャプチャから双方向フロー CSV を生成し、その集合を特徴量 JSON に要約するためのディレクトリです。可視化スクリプトはこのディレクトリではなく [../graph/plot_flow_features.py](../graph/plot_flow_features.py) にあります。

## 使い方

### 1. pcap から flow CSV を作る

- スクリプト: `pcap_to_flow.py`
- 必須オプション:
  - `--input`
- 互換オプション:
  - `--input_path` でも入力指定可能
- 主なデフォルト:
  - 出力先を省略した場合: `results/flows/all/<input_name>/flows.csv`
  - 進捗表示間隔: `--progress-every 1000000`
- 最小実行例:

```bash
python scripts/flow/pcap_to_flow.py \
  --input data/raw/202604080000.pcap.gz
```

### 2. flow CSV を features JSON に要約する

- スクリプト: `summarize_flow_features.py`
- 必須オプション:
  - `--input`
- 主なデフォルト:
  - 全体 flow CSV `results/flows/all/<dataset>/flows.csv` を入力した場合: `results/features/all/<dataset>/features.json`
  - `results/flows/prefix/...` 配下の CSV を入力した場合: `results/features/prefix/.../<input_stem>_features.json`
  - ヒストグラム bin 数: `--hist-bins 20`
  - 上位フロー記録数: `--top-n 20`
- 最小実行例:

```bash
python scripts/flow/summarize_flow_features.py \
  --input results/flows/all/202604080000/flows.csv
```

### 3. features JSON を可視化する

- 実配置: `scripts/graph/plot_flow_features.py`
- 必須オプション:
  - `--input`
- 主なデフォルト:
  - ベース出力先: `results/flow_plots/all`
  - 実際の保存先: `results/flow_plots/all/<dataset_name>/`
  - 生成対象: `--graph all`
  - 上位フロー表示数: `--top-n 10`
- 最小実行例:

```bash
python scripts/graph/plot_flow_features.py \
  --input results/features/all/202604080000/features.json
```

## パイプライン

```text
pcap.gz / pcap / pcapng / pcapng.gz
  ↓
pcap_to_flow.py
  ↓
results/flows/all/<dataset>/flows.csv
  ↓
summarize_flow_features.py
  ↓
results/features/all/<dataset>/features.json
  ↓
../graph/plot_flow_features.py
  ↓
results/flow_plots/all/<dataset_name>/*.png
```

prefix ごとの flow CSV を要約する場合は、入力 CSV が `results/flows/prefix/` 配下にあるため、出力も対応する `results/features/prefix/` 配下に自動で振り分けられます。

## スクリプト詳細

### `pcap_to_flow.py`

- 役割:
  - TCP/UDP パケットを双方向 5 タプル単位のフローに集約します。
- 入力:
  - `pcap`
  - `pcap.gz`
  - `pcapng`
  - `pcapng.gz`
- 出力:
  - CSV
- デフォルト出力先:
  - `results/flows/all/<input_name>/flows.csv`
- 対象:
  - IPv4 / IPv6
  - TCP / UDP のみ
- 非対象:
  - 非 IP パケット
  - TCP / UDP 以外の IP パケット
- フロー化の扱い:
  - `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol` を用いてキーを作ります。
  - A→B と B→A は同一フローになるよう正規化します。
  - 出力上の `src_*` / `dst_*` はソート順ではなく、最初に観測した方向で固定されます。
  - フロータイムアウトは設けず、キャプチャ全体を通して EOF まで集約します。
- 主な出力列:
  - `flow_id`
  - `start_time`
  - `end_time`
  - `src_ip`
  - `src_port`
  - `dst_ip`
  - `dst_port`
  - `protocol`
  - `duration`
  - `packet_count`
  - `byte_count`
  - `pps`
  - `bps`
  - `packets_from_src`
  - `packets_from_dst`
  - `bytes_from_src`
  - `bytes_from_dst`
  - `syn_count`
  - `syn_ack_count`
  - `ack_count`
  - `fin_count`
  - `rst_count`
- 補足:
  - `byte_count` は Ethernet フレーム長 `len(buf)` ベースで集計されます。
  - 実行時には総パケット数、スキップ数、パースエラー数、生成フロー数が標準出力に表示されます。

### `summarize_flow_features.py`

- 役割:
  - flow CSV を読み込み、統計量、ヒストグラム、上位フロー情報を持つ `features.json` を生成します。
- 入力:
  - `pcap_to_flow.py` の出力 CSV
  - `scripts/prefix/filter_flows_by_prefix.py` で切り出した prefix 別 CSV
- 出力:
  - 全体 flow では `features.json`
  - prefix flow では `*_features.json`
- デフォルト出力先:
  - 全体 flow: `results/features/all/<dataset>/features.json`
  - prefix flow: `results/features/prefix/<dataset>/<prefix>_features.json`
- 入力 CSV に必須の列:
  - `flow_id`
  - `start_time`
  - `end_time`
  - `src_ip`
  - `src_port`
  - `dst_ip`
  - `dst_port`
  - `protocol`
  - `duration`
  - `packet_count`
  - `byte_count`
  - `pps`
  - `bps`
  - `packets_from_src`
  - `packets_from_dst`
  - `bytes_from_src`
  - `bytes_from_dst`
  - `syn_count`
  - `syn_ack_count`
  - `ack_count`
  - `fin_count`
  - `rst_count`
- 主な数値特徴:
  - `flow_inter_arrival_time`
  - `duration`
  - `packet_count`
  - `byte_count`
  - `pps`
  - `bps`
  - `avg_packet_size`
  - `packets_from_src_ratio`
  - `bytes_from_src_ratio`
- 生成内容:
  - 各特徴量の基本統計量
  - 線形ヒストグラム
  - 対数ヒストグラム
  - プロトコル別サマリ
  - TCP flag 総数と flow あたり平均
  - behavioral indicators
  - 上位フロー一覧
  - 不正行数と代表的な不正行例
- behavioral indicators:
  - `short_flow_ratio_le_1s`
  - `tiny_flow_ratio_le_3packets`
  - `rst_observed_flow_ratio`
  - `syn_only_like_flow_ratio`
- 補足:
  - 不正行は処理全体を止めずにスキップされ、件数と代表例だけ JSON に残します。
  - `syn_only_like_flow_ratio` は、`syn_count > 0` かつ `ack_count == 0` かつ `byte_count == 0` のフロー比率です。

### `../graph/plot_flow_features.py`

- 役割:
  - `summarize_flow_features.py` の JSON を PNG 群に可視化します。
- 入力:
  - `features.json`
- 出力:
  - `results/flow_plots/all/<dataset_name>/`
  - `--outdir` を変更した場合は `<outdir>/<dataset_name>/`
- 主なオプション:
  - `--graph`
    - `features`
    - `tcp_flags`
    - `behavior`
    - `top`
    - `protocol`
    - `all`
  - `--features`
    - 可視化する特徴量名のリスト
  - `--top-n`
    - 上位フロー図に含める件数
- 主な生成物:
  - 各特徴量のヒストグラム
  - 推奨特徴量の対数ヒストグラム
  - `tcp_flag_totals.png`
  - `tcp_flag_rates_per_flow.png`
  - `behavioral_indicators.png`
  - `protocol_flow_counts.png`
  - `protocol_flow_ratios.png`
  - `top_flows_by_<key>.png`
- 補足:
  - dataset 名は JSON の `scope.dataset_name` を優先し、なければ入力ファイル名から決まります。
  - 標本数が 30 未満のときは図中に `small sample` 注記が入ります。

## 追加の実行例

### 出力先を明示して flow CSV を作る

```bash
python scripts/flow/pcap_to_flow.py \
  --input data/raw/sample.pcapng \
  --output results/flows/all/sample/flows.csv
```

### prefix 別 flow CSV を要約する

```bash
python scripts/flow/summarize_flow_features.py \
  --input results/flows/prefix/202604080000/dst_192.168.75.136_32.csv
```

### 可視化対象を絞る

```bash
python scripts/graph/plot_flow_features.py \
  --input results/features/all/202604080000/features.json \
  --graph protocol
```
