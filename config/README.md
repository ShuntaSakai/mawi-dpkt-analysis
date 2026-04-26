# config/

`config/` には解析時の設定ファイルを配置します。

## 使い方

### まず確認する設定

- prefix 評価を行う場合:
  - `scripts/prefix/evaluate_prefixes.py` は既定で `config/prefix_selection.yaml` を参照します
  - 明示的に切り替える場合だけ `--config <path>` を指定します
- 旧バッチ系を使う場合:
  - `config/settings.yaml` を参照します
  - 現行の flow / prefix パイプラインとは出力先が異なります

### `prefix_selection.yaml` を調整する場面

- 小さいテスト用データでは `min_flows`、`min_packets`、`min_bytes` を下げます
- 候補が厳しすぎる場合は `max_short_flow_ratio` や `max_tiny_flow_ratio` を見直します
- 上位候補数を変えたい場合は `top_k` を調整します
- スコア付けの重みを変えたい場合は `score_weights` を調整します

### 参照先

- `prefix_selection.yaml`
  - 利用箇所: `scripts/prefix/evaluate_prefixes.py`
- `settings.yaml`
  - 利用箇所: `scripts/download_one.py`、`scripts/analyze_one.py`、`scripts/run_batch.py`

## 設定ファイル詳細

### `prefix_selection.yaml`

- 役割: prefix 評価・選定の閾値とスコア重みを管理します
- 利用箇所: `scripts/prefix/evaluate_prefixes.py`
- 必須キー:
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

#### 現在の主な設定値

- `prefix_len: 24`
- `min_flows: 100`
- `min_packets: 1000`
- `min_bytes: 100000`
- `max_short_flow_ratio: 0.8`
- `max_tiny_flow_ratio: 0.8`
- `max_syn_only_like_ratio: 0.5`
- `max_rst_observed_ratio: 0.8`
- `short_duration_threshold: 1.0`
- `tiny_packet_threshold: 3`
- `top_k: 10`

#### `score_weights`

- `flow_count: 0.20`
- `packet_count: 0.20`
- `byte_count: 0.20`
- `low_short_flow_ratio: 0.15`
- `low_tiny_flow_ratio: 0.15`
- `low_syn_only_like_ratio: 0.10`

`evaluate_prefixes.py` は `score_weights` を必須キーとして検証し、合計が 1.0 でない場合は内部で正規化します。

#### 解釈上の注意

- `prefix_len` は候補 prefix の広さの基準です
- `short_duration_threshold` と `tiny_packet_threshold` は短命 flow・tiny flow 判定の閾値です
- `max_*_ratio` は除外ではなく、`passes_filters` や `scan_candidate` 判定の基準として使われます
- 小規模データで本番向け閾値をそのまま使うと、候補がほとんど残らないことがあります

### `settings.yaml`

- 役割: 旧バッチ系スクリプトの設定です
- 主な内容:
  - `mawi.base_url`
  - `mawi.start`
  - `mawi.end`
  - `mawi.interval_minutes`
  - `paths.raw_dir`
  - `paths.json_dir`
  - `paths.plot_dir`
  - `paths.log_dir`
  - `paths.state_dir`
  - `run.sleep_seconds_between_jobs`
  - `run.delete_raw_after_success`
  - `run.retain_failed_files`
  - `run.generate_plots`
  - `run.graph_type`
- 補足:
  - 出力先は `results/json` と `results/plots` で、現行の `results/flows` / `results/features` 系とは別系統です
