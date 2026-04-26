# scripts/flow/

`scripts/flow/` は、pcap から flow CSV を生成し、flow 集合の特徴量を要約するためのディレクトリです。可視化は [../graph/](../graph/) のスクリプトを使います。

## パイプライン

```text
pcap.gz
  ↓
pcap_to_flow.py
  ↓
results/flows/all/*.csv
  ↓
summarize_flow_features.py
  ↓
results/features/all/*_features.json
  ↓
../graph/plot_flow_features.py
  ↓
results/flow_plots/all/<dataset_name>/*.png
```

## スクリプト

### `pcap_to_flow.py`

- 役割: パケット列を双方向 5 タプルの flow に集約します
- 入力: `data/raw/*.pcap.gz`、`*.pcap`、`*.pcapng` など
- 出力: `results/flows/all/*.csv`
- 対象:
  - IPv4 / IPv6
  - TCP / UDP のみ
- フロー化:
  - `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol` を基に正規化します
  - A→B と B→A は同一 flow として扱います
  - 最初に観測した向きを `src` / `dst` として保持します

### `summarize_flow_features.py`

- 役割: flow CSV から `features.json` を生成します
- 入力: flow CSV
- 出力:
  - 全体 flow の場合: `results/features/all/*_features.json`
  - prefix flow の場合: `results/features/prefix/.../*_features.json`
- 主な要約対象:
  - `duration`
  - `packet_count`
  - `byte_count`
  - `pps`
  - `bps`
  - `avg_packet_size`
  - `directionality` 相当の比率
    - `packets_from_src_ratio`
    - `bytes_from_src_ratio`
  - TCP flags
  - behavioral indicators
    - `short_flow_ratio`
    - `tiny_flow_ratio`
    - `rst_observed_flow_ratio`
    - `syn_only_like_flow_ratio`

### `../graph/plot_flow_features.py`

- 役割: `features.json` を PNG に可視化します
- 入力: `features.json`
- 出力: `results/flow_plots/<scope>/<dataset_name>/*.png`
- 生成対象:
  - 各特徴量のヒストグラム
  - log ヒストグラム
  - TCP flag 集計
  - behavioral indicators
  - protocol summary
  - 上位 flow の可視化

## 実行例

```bash
python scripts/flow/pcap_to_flow.py \
  --input data/raw/202604080000.pcap.gz

python scripts/flow/summarize_flow_features.py \
  --input results/flows/all/202604080000.csv

python scripts/graph/plot_flow_features.py \
  --input results/features/all/202604080000_features.json
```
