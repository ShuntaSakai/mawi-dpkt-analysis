# config/

`config/` には解析時の設定ファイルを配置します。

## `prefix_selection.yaml`

- 役割: prefix 評価・選定の閾値とスコア重みを管理します
- 利用箇所: `scripts/prefix/evaluate_prefixes.py`

### 主な設定項目

- `prefix_len`
- `min_flows`
- `min_packets`
- `min_bytes`
- `max_short_flow_ratio`
- `max_tiny_flow_ratio`
- `max_syn_only_like_ratio`
- `max_rst_observed_ratio`
- `short_duration_threshold`
- `tiny_packet_threshold`
- `top_k`
- `score_weights`

### 補足

- 小さいテスト用データでは、`min_flows`、`min_packets`、`min_bytes` などの閾値を下げる必要があります
- `score_weights` は flow 数、packet 数、byte 数、および低い短命率・小規模率・SYN-only-like 率をどの程度重視するかを表します

## その他

- `settings.yaml`
  - `download_one.py`、`analyze_one.py`、`run_batch.py` で使う旧バッチ系の設定です
  - 現行の主系統である flow / prefix パイプラインとは出力先が異なります
