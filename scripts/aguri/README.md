# scripts/aguri/

`scripts/aguri/` は、`aguri3` / `agurim` を用いて MAWI から prefix 候補を抽出するためのディレクトリです。

aguri の出力は候補抽出のために使い、最終的な prefix 選定は [../prefix/evaluate_prefixes.py](../prefix/evaluate_prefixes.py) で flow 特徴量に基づいて行います。

## パイプライン

```text
pcap.gz
  ↓
run_aguri.py
  ↓
results/aguri/<dataset>/<dataset>.agr
results/aguri/<dataset>/<dataset>.agurim.txt
  ↓
parse_agurim.py
  ↓
results/aguri/<dataset>/<dataset>.aguri_candidates.csv
```

## スクリプト

### `run_aguri.py`

- 役割: `aguri3` と `agurim` を順に実行します
- 入力: `pcap` / `pcap.gz` / `pcapng` / `pcapng.gz`
- 出力:
  - `.agr`
  - `.agurim.txt`
- 既定出力先: `results/aguri/<dataset>/`

### `parse_agurim.py`

- 役割: `agurim` のテキスト出力を CSV に変換します
- 入力: `.agurim.txt`
- 出力: `aguri_candidates.csv`
- 主な列:
  - `aggregate_id`
  - `src_prefix`
  - `dst_prefix`
  - `bytes`
  - `byte_ratio`
  - `packets`
  - `packet_ratio`
  - `tcp_byte_ratio`
  - `tcp_packet_ratio`
  - `udp_byte_ratio`
  - `udp_packet_ratio`
  - `protocol_breakdown`

## 実行例

```bash
python scripts/aguri/run_aguri.py \
  --pcap data/raw/http_traffic.pcap.gz \
  --dataset http_traffic

python scripts/aguri/parse_agurim.py \
  --input results/aguri/http_traffic/http_traffic.agurim.txt
```
