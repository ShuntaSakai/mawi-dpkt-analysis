# config/

`config/` には解析時の設定ファイルを配置します。ここは人間が閾値やパスを調整する前提なので、各定数が何を表し、値を変えると何が変わるかを明確にしておく必要があります。

## 使い方

### まず確認する設定

- prefix 評価を行う場合:
  - `scripts/prefix/evaluate_prefixes.py` は既定で `config/prefix_selection.yaml` を参照します
  - 別ファイルを使う場合だけ `--config <path>` を指定します
  - 小さいサンプル PCAP では `config/prefix_selection.sample.yaml` の利用を優先してください
- 旧バッチ系を使う場合:
  - `config/settings.yaml` を参照します
  - 現行の flow / prefix パイプラインとは出力先も役割も異なります

### 設定変更の基本方針

- 小さいテストデータでは `min_flows`、`min_packets`、`min_bytes` を下げる
- 候補が落ちすぎる場合は `max_*_ratio` を緩める
- scan 的な prefix を拾いやすくしたいか、通常通信寄りの prefix を優先したいかで `score_weights` を調整する
- パス設定を変更する場合は、後続スクリプトがどこを読むかを必ず合わせる

## 設定ファイル詳細

### `prefix_selection.yaml`

- 役割:
  - prefix 候補の評価・選定に使う閾値とスコア重みを定義します
- 利用箇所:
  - `scripts/prefix/evaluate_prefixes.py`
- 前提:
  - aguri の候補をそのまま採用せず、flow 特徴量で再評価するための設定です

#### 現在の設定値

```yaml
prefix_len: 24

min_flows: 100
min_packets: 1000
min_bytes: 100000

max_short_flow_ratio: 0.8
max_tiny_flow_ratio: 0.8
max_syn_only_like_ratio: 0.5
max_rst_observed_ratio: 0.8

short_duration_threshold: 1.0
tiny_packet_threshold: 3

top_k: 10

score_weights:
  flow_count: 0.20
  packet_count: 0.20
  byte_count: 0.20
  low_short_flow_ratio: 0.15
  low_tiny_flow_ratio: 0.15
  low_syn_only_like_ratio: 0.10
```

#### 必須キー一覧

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

#### 各定数の意味

- `prefix_len`
  - 何を表すか:
    - IPv4 で「この程度の広さを基準にしたい」という目安です
  - コード上の使われ方:
    - `prefix_is_broader_than_target` と `prefix_specificity_ratio` の計算に使われます
    - `/24` を基準にすると、`/16` のような広すぎる prefix は具体性が低い候補として扱われます
  - 値を大きくすると:
    - より細かい prefix を基準に評価します
    - `/24` より細かい `/25` や `/32` を相対的に許容しやすくなります
  - 値を小さくすると:
    - より広い prefix でも基準から外れにくくなります
  - 注意:
    - これは「prefix を強制的に切る長さ」ではなく、広さの評価基準です

- `min_flows`
  - 何を表すか:
    - prefix を採用候補として残すために必要な最小 flow 数です
  - コード上の使われ方:
    - `passes_filters` 判定で `flow_count >= min_flows` を要求します
  - 値を大きくすると:
    - 標本数の少ない prefix が落ちやすくなります
    - 解釈の安定性は上がりやすいですが、小規模でも意味のある prefix を逃しやすくなります
  - 値を小さくすると:
    - 小規模 prefix も通りやすくなります
    - ただし比較結果が不安定になりやすいです

- `min_packets`
  - 何を表すか:
    - prefix に含まれる総 packet 数の下限です
  - コード上の使われ方:
    - `passes_filters` 判定で `packet_count >= min_packets` を要求します
  - 値を大きくすると:
    - packet 数の少ない通信を落としやすくなります
  - 値を小さくすると:
    - 短時間・少 packet の prefix も候補に残ります

- `min_bytes`
  - 何を表すか:
    - prefix に含まれる総 byte 数の下限です
  - コード上の使われ方:
    - `passes_filters` 判定で `byte_count >= min_bytes` を要求します
  - 値を大きくすると:
    - 極小トラフィックな prefix を落としやすくなります
  - 値を小さくすると:
    - パケット数はあっても通信量の少ない prefix も残りやすくなります

- `max_short_flow_ratio`
  - 何を表すか:
    - 短命 flow の比率の上限です
  - コード上の使われ方:
    - `passes_filters` 判定で `short_flow_ratio <= max_short_flow_ratio`
    - `scan_candidate` 判定でも参照されます
  - 依存する定数:
    - `short_duration_threshold`
  - 値を小さくすると:
    - 短命 flow が多い prefix を厳しく落とします
  - 値を大きくすると:
    - 短命 flow が多い prefix も通しやすくなります
  - 注意:
    - 短命 flow が多いことは scan と整合的な場合がありますが、即座に異常とは限りません

- `max_tiny_flow_ratio`
  - 何を表すか:
    - tiny flow の比率の上限です
  - コード上の使われ方:
    - `passes_filters` 判定で `tiny_flow_ratio <= max_tiny_flow_ratio`
    - `scan_candidate` 判定でも参照されます
  - 依存する定数:
    - `tiny_packet_threshold`
  - 値を小さくすると:
    - 小 packet 数 flow が多い prefix を厳しく落とします
  - 値を大きくすると:
    - tiny flow 主体の prefix も残しやすくなります

- `max_syn_only_like_ratio`
  - 何を表すか:
    - SYN-only-like flow の比率の上限です
  - コード上の使われ方:
    - `passes_filters` 判定で `syn_only_like_ratio <= max_syn_only_like_ratio`
    - `scan_candidate` 判定でも参照されます
  - この指標の定義:
    - `protocol == TCP`
    - `syn_count > 0`
    - `ack_count == 0`
    - `packet_count <= tiny_packet_threshold`
    - を満たす flow の割合です
  - 値を小さくすると:
    - scan 的な候補を通常候補から落としやすくなります
  - 値を大きくすると:
    - SYN 主体の prefix も候補に残しやすくなります

- `max_rst_observed_ratio`
  - 何を表すか:
    - RST を含む flow の比率の上限です
  - コード上の使われ方:
    - `passes_filters` 判定で `rst_observed_ratio <= max_rst_observed_ratio`
  - 値を小さくすると:
    - RST が多い prefix を厳しく落とします
  - 値を大きくすると:
    - RST の多い prefix も残しやすくなります
  - 注意:
    - RST が多いことだけで異常と断定する設計ではありません

- `short_duration_threshold`
  - 何を表すか:
    - 何秒以下を短命 flow と見なすかの閾値です
  - 単位:
    - 秒
  - コード上の使われ方:
    - `duration <= short_duration_threshold` を `is_short_flow` として計算します
  - 値を小さくすると:
    - 「短命」と判定される flow が減ります
  - 値を大きくすると:
    - 「短命」と判定される flow が増えます

- `tiny_packet_threshold`
  - 何を表すか:
    - 何 packet 以下を tiny flow と見なすかの閾値です
  - 単位:
    - packet 数
  - コード上の使われ方:
    - `packet_count <= tiny_packet_threshold` を `is_tiny_flow` として計算します
    - SYN-only-like 判定にも使われます
  - 値を小さくすると:
    - tiny flow 判定が厳しくなります
  - 値を大きくすると:
    - より多くの flow が tiny 扱いになります

- `top_k`
  - 何を表すか:
    - `passes_filters == True` の候補から最終的に何件を `selected_prefixes.csv` に残すかの上限です
  - コード上の使われ方:
    - score 順に並べたあと `head(top_k)` が選ばれます
  - 値を大きくすると:
    - 比較対象の prefix 数が増えます
  - 値を小さくすると:
    - 厳選した少数候補だけが残ります

#### `score_weights`

- 役割:
  - `passes_filters` を通った候補ではなく、全候補に対して相対評価の score を付けるための重みです
- 注意:
  - `evaluate_prefixes.py` は合計が 1.0 でない場合、内部で正規化します
  - すべて非負である必要があります

各キーの意味:

- `flow_count`
  - flow 数が多い prefix を高く評価する重みです
- `packet_count`
  - packet 数が多い prefix を高く評価する重みです
- `byte_count`
  - byte 数が多い prefix を高く評価する重みです
- `low_short_flow_ratio`
  - 短命 flow 比率が低い prefix を高く評価する重みです
- `low_tiny_flow_ratio`
  - tiny flow 比率が低い prefix を高く評価する重みです
- `low_syn_only_like_ratio`
  - SYN-only-like 比率が低い prefix を高く評価する重みです

調整の考え方:

- 通信量重視にしたい場合:
  - `flow_count`、`packet_count`、`byte_count` を上げる
- scan 的候補を下げたい場合:
  - `low_short_flow_ratio`、`low_tiny_flow_ratio`、`low_syn_only_like_ratio` を上げる
- scan 的 prefix も研究対象として残したい場合:
  - 閾値を緩めつつ、score 重みで順位を調整する方が扱いやすいです

#### 運用上の注意

- `max_*_ratio` は「単純除外」のためだけでなく、`scan_candidate` の補助判定にも使われます
- 小規模データで本番向け閾値をそのまま使うと、候補がほとんど残らないことがあります
- `scan_candidate` が立っても、研究対象として保持する設計です
- 解釈は断定ではなく、「可能性がある」「示唆する」という扱いを前提にしてください

### `prefix_selection.sample.yaml`

- 役割:
  - `http_traffic.pcap.gz` のような非常に小さいサンプル PCAP でも、prefix パイプライン全体の疎通確認をしやすくするための設定です
- 想定用途:
  - `flow_num` や `total_packets` が小さく、本番閾値では `selected_prefixes.csv` が空になりやすいケース
- 方針:
  - `min_flows`、`min_packets`、`min_bytes` を 1 まで下げます
  - 比率系の閾値と score 重みは本番設定と揃え、解釈軸はできるだけ維持します
- 使い方:

```bash
python scripts/pipeline/run_full_prefix_pipeline.py \
  --pcap data/raw/http_traffic.pcap.gz \
  --config config/prefix_selection.sample.yaml \
  --force
```

### `settings.yaml`

- 役割:
  - `scripts/download_one.py`、`scripts/analyze_one.py`、`scripts/run_batch.py` で使う旧バッチ系の設定です
- 利用箇所:
  - 主に `scripts/run_batch.py`
- 注意:
  - 出力先は `results/json` と `results/plots` で、現行の `results/flows` / `results/features` 系とは別系統です

#### 現在の設定値

```yaml
mawi:
  base_url: "https://mawi.wide.ad.jp/mawi/ditl/ditl2026"
  start: "202604080000"
  end: "202604080045"
  interval_minutes: 15

paths:
  raw_dir: "data/raw"
  json_dir: "results/json"
  plot_dir: "results/plots"
  log_dir: "logs"
  state_dir: "state"

run:
  sleep_seconds_between_jobs: 5
  delete_raw_after_success: true
  retain_failed_files: true
  generate_plots: true
  graph_type: "all"
  progress_every: 1000000
  max_packets: null
  min_free_gib_before_download: 10
```

#### `mawi` セクション

- `base_url`
  - 何を表すか:
    - MAWI データ取得元のベース URL です
  - コード上の使われ方:
    - `run_batch.py` が `<base_url>/<timestamp>.pcap.gz` を組み立てます
  - 変更する場面:
    - 年度ディレクトリや配布元が変わったとき

- `start`
  - 何を表すか:
    - バッチ処理対象の開始時刻です
  - 形式:
    - `YYYYMMDDHHMM`
  - コード上の使われ方:
    - `generate_timestamps()` の開始点になります
  - 注意:
    - JST 文字列として扱っているわけではなく、単に指定フォーマットの時刻列です

- `end`
  - 何を表すか:
    - バッチ処理対象の終了時刻です
  - 形式:
    - `YYYYMMDDHHMM`
  - コード上の使われ方:
    - `generate_timestamps()` の終了点になります
  - 注意:
    - `start` から `end` までを含む範囲で列挙されます

- `interval_minutes`
  - 何を表すか:
    - `start` から `end` まで何分間隔でファイルを取りに行くかです
  - 単位:
    - 分
  - 例:
    - `15` なら 15 分刻み
  - 値を小さくすると:
    - 対象ファイル数が増えます
  - 値を大きくすると:
    - 対象ファイル数が減ります

#### `paths` セクション

- `raw_dir`
  - 何を表すか:
    - ダウンロードした `pcap.gz` の保存先です
  - コード上の使われ方:
    - `download_one.py` の出力先
    - `run_batch.py` の空き容量チェック対象

- `json_dir`
  - 何を表すか:
    - `analyze_one.py` が出力する旧系統 JSON の保存先です
  - 注意:
    - 現行の `results/features/` とは別物です

- `plot_dir`
  - 何を表すか:
    - 旧系統の可視化結果の保存先です
  - 注意:
    - 現行の `results/flow_plots/` とは別物です

- `log_dir`
  - 何を表すか:
    - `run_batch.py` が書く JSONL ログの保存先です
  - 生成物:
    - `run_batch_<timestamp>.jsonl`

- `state_dir`
  - 何を表すか:
    - バッチの処理状態を記録するファイル群の保存先です
  - 主なファイル:
    - `processed.txt`
    - `failed.txt`
    - `retained.txt`

#### `run` セクション

- `sleep_seconds_between_jobs`
  - 何を表すか:
    - 1 ファイル処理後に次の処理へ進む前の待機時間です
  - 単位:
    - 秒
  - 値を大きくすると:
    - 連続アクセスが抑えられますが、全体の処理時間は長くなります

- `delete_raw_after_success`
  - 何を表すか:
    - 解析とプロットが成功したあと、元の `pcap.gz` を削除するかどうかです
  - `true` の場合:
    - ディスク使用量を抑えられます
  - `false` の場合:
    - raw を再利用できます

- `retain_failed_files`
  - 何を表すか:
    - エラー時に raw を残す方針です
  - 現状の補足:
    - この値は設定として存在しますが、`run_batch.py` 側では主に `retained.txt` への記録と削除失敗時の保持で運用されています
  - 注意:
    - 将来的に動作条件と完全一致しているかはコード側も確認してください

- `generate_plots`
  - 何を表すか:
    - `analyze_one.py` の JSON 生成後に可視化も実行するかどうかです
  - `true` の場合:
    - 追加で plot ステップを走らせます
  - `false` の場合:
    - JSON 生成までで止まります

- `graph_type`
  - 何を表すか:
    - 旧系統の plot スクリプトに渡すグラフ種別です
  - 使い方:
    - `run_batch.py` が `--graph <graph_type>` として渡します
  - 注意:
    - 現行の `scripts/graph/plot_flow_features.py` の `--graph` とは別系統の設定です

- `progress_every`
  - 何を表すか:
    - `analyze_one.py` が進捗を何 packet ごとに表示するかです
  - 単位:
    - packet 数
  - `0` より大きい場合:
    - 指定 packet 数ごとに progress を出します

- `max_packets`
  - 何を表すか:
    - `analyze_one.py` で先頭から最大何 packet まで読むかの上限です
  - `null` の場合:
    - 全 packet を処理します
  - 小さい値を入れる場面:
    - 動作確認や簡易テスト

- `min_free_gib_before_download`
  - 何を表すか:
    - ダウンロード前に必要な最小空き容量です
  - 単位:
    - GiB
  - コード上の使われ方:
    - `run_batch.py` が `raw_dir` の空き容量を見て、これ未満ならダウンロードをスキップします
  - 値を大きくすると:
    - ディスク安全性は上がりますが、処理を開始しにくくなります

## 人が設定をいじるときの実務メモ

- まず変更理由を決める:
  - 小規模テスト対応なのか
  - scan 的 prefix を残したいのか
  - 通常通信寄りの prefix を優先したいのか
- 一度に多くを変えすぎない:
  - `min_flows`、`min_packets`、`min_bytes` と `max_*_ratio` を同時に大きく変えると、どの変更が効いたか追いづらくなります
- 閾値変更後は必ず出力を確認する:
  - `results/prefix/<dataset>/prefix_evaluation.csv`
  - `results/prefix/<dataset>/selected_prefixes.csv`
- README の説明よりコードが優先:
  - 挙動を最終確認したい場合は `scripts/prefix/evaluate_prefixes.py` と `scripts/run_batch.py` の利用箇所を確認してください
