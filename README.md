# mawi-dpkt-analysis

MAWI の pcap.gz トレースを gzip 圧縮のまま逐次読み込みし、`dpkt` で通信統計を集計・可視化するためのプロジェクト。

現在は 1 本の pcap.gz を対象に、ダウンロード、解析 JSON 生成、グラフ生成を行う。デフォルトの対象は MAWI DITL 2026 の `202604080000.pcap.gz`。

## セットアップ

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

主な依存ライブラリ:

- `dpkt`: pcap 解析
- `matplotlib`: グラフ生成
- `PyYAML`: 設定ファイル利用時の YAML 読み込み

## ダウンロード

```bash
python scripts/download_one.py
```

デフォルトでは次の URL から `data/raw/` へ保存する。

```text
https://mawi.wide.ad.jp/mawi/ditl/ditl2026/202604080000.pcap.gz
```

オプション:

- `--url`: ダウンロード対象 URL。デフォルトは上記 MAWI URL
- `--outdir`: 保存先ディレクトリ。相対パスはリポジトリルート基準で解決される。デフォルトは `data/raw`
- `--force`: 既存ファイルがある場合も上書きダウンロードする

## 解析

```bash
python scripts/analyze_one.py
```

デフォルトでは `data/raw/202604080000.pcap.gz` を読み込み、`results/json/202604080000.json` へ解析結果を書き出す。

オプション:

- `--input`: 入力する `.pcap.gz` ファイル。デフォルトは `data/raw/202604080000.pcap.gz`
- `--outdir`: JSON 出力先ディレクトリ。相対パスはリポジトリルート基準で解決される。デフォルトは `results/json`
- `--progress-every`: 指定パケット数ごとに進捗を表示する。デフォルトは `1000000`
- `--max-packets`: 指定パケット数で解析を打ち切る。動作確認用

## 出力 JSON

解析結果は 1 つの JSON オブジェクトとして保存される。

基本統計:

- `file`: 入力ファイルパス
- `started_at_epoch`, `finished_at_epoch`: 解析開始・終了時刻
- `elapsed_seconds`, `packets_per_second`: 解析時間と処理速度
- `packets_total`, `bytes_total`: 総パケット数と総バイト数
- `first_timestamp`, `last_timestamp`: pcap 内の最初・最後のタイムスタンプ
- `ethernet_parse_error`, `ip_parse_error`: 解析エラー数

プロトコル別カウント:

- `non_ip`, `ipv4`, `ipv6`: IP バージョンまたは非 IP パケットの件数
- `tcp`, `udp`, `icmp`, `arp`: 主要プロトコル別の件数
- `layer4_protocols`: L4 プロトコル別件数。各要素は `{ "protocol": string, "packets": number }`

TCP フラグ集計:

- `tcp_syn`, `tcp_ack`, `tcp_fin`, `tcp_rst`: TCP フラグ別の出現パケット数
- `tcp_flag_counts`: TCP フラグ名別の件数。各要素は `{ "flag": string, "packets": number }`
- `top_tcp_flag_combinations`: TCP フラグ組み合わせ別の件数。各要素は `{ "flag": string, "packets": number }`
- `top_syn_flows`: SYN を含む TCP フロー上位 20 件。各要素は `{ "flow": string, "packets": number }`

上位集計:

- `top_destination_ports`: 宛先ポート上位 20 件。各要素は `{ "port": number, "packets": number }`
- `top_source_ports`: 送信元ポート上位 20 件。各要素は `{ "port": number, "packets": number }`
- `top_source_ips`: 送信元 IP 上位 20 件。各要素は `{ "ip": string, "packets": number }`
- `top_destination_ips`: 宛先 IP 上位 20 件。各要素は `{ "ip": string, "packets": number }`
- `top_source_endpoints`: 送信元 `IP:port` 上位 20 件。各要素は `{ "endpoint": string, "packets": number }`
- `top_destination_endpoints`: 宛先 `IP:port` 上位 20 件。各要素は `{ "endpoint": string, "packets": number }`
- `top_flows`: `PROTO src_ip:src_port -> dst_ip:dst_port` 形式のフロー上位 20 件。各要素は `{ "flow": string, "packets": number }`
- `packets_per_minute_top20`: 分単位のパケット数上位 20 件。各要素は `{ "minute": "YYYY-MM-DD HH:MM", "packets": number }`

## グラフ生成

```bash
python scripts/graph/plot_from_json.py --input results/json/202604080000.json
```

デフォルトでは `results/plots/` へ PNG を出力する。`--outdir` に相対パスを指定した場合は、リポジトリルート基準で解決される。

オプション:

- `--input`: 入力する解析 JSON。必須
- `--outdir`: グラフ出力先ディレクトリ。デフォルトは `results/plots`
- `--graph`: 生成するグラフ。`tcp_flags`、`top_flows`、`flow_size_distribution`、`all` から選択する。デフォルトは `all`
- `--top-n`: `top_flows` グラフに表示するフロー数。デフォルトは `10`

生成されるグラフ:

- `tcp_flag_distribution.png`: `tcp_flag_counts` を使った TCP フラグ分布
- `top_flows_packets.png`: `top_flows` を使った上位フローランキング
- `flow_size_distribution_packets.png`: `top_flows` の `packets` を使った簡易的なフローサイズ分布

グラフの選定理由:

本プロジェクトでは、単純なトラフィック量の時間変化ではなく、通信の構造や特徴を把握するためのグラフを優先している。

- フローサイズ分布: 多数の小さなフローと少数の大きなフローという、トラフィック構造の偏りを確認するため
- Top フローランキング: 全体の中で支配的な通信や、特定 IP 間に集中している通信を見つけやすくするため
- TCP フラグ分布: SYN、ACK、FIN、RST などから、接続開始、通常通信、正常終了、異常終了といった通信状態を把握するため

観点ごとの対応:

| 観点 | グラフ |
|------|--------|
| トラフィック構造 | フローサイズ分布 |
| 支配的通信 | Top フローランキング |
| 通信状態 | TCP フラグ分布 |

注意点:

- 現状のフローサイズ分布は `top_flows` のみを対象にしており、全フロー分布ではない
- 現状の Top フロー可視化はパケット数ベースであり、バイト数ベースではない

## ディレクトリ

- `scripts/download_one.py`: pcap.gz を 1 ファイル取得するスクリプト
- `scripts/analyze_one.py`: pcap.gz を 1 ファイル解析して JSON を出力するスクリプト
- `scripts/graph/plot_from_json.py`: 解析 JSON から PNG グラフを生成するスクリプト
- `data/raw/`: ダウンロードした pcap.gz の保存先
- `results/json/`: 解析結果 JSON の保存先
- `results/plots/`: 生成したグラフ PNG の保存先
- `config/`: 設定ファイル用ディレクトリ
- `state/`: 処理状態管理用ディレクトリ

## 方針

- pcap.gz は展開せず、gzip 圧縮のまま逐次読み込みする
- 巨大な pcap.gz や解析結果は Git 管理しない
- 相対パスの出力先は原則としてリポジトリルート基準で扱う
- まずは 1 ファイル単位で性能と出力仕様を確認し、必要に応じて複数ファイル処理へ拡張する
