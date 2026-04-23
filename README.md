# mawi-dpkt-analysis

MAWI の pcap.gz トレースを、展開せずに gzip 圧縮のまま逐次読み込みし、
`dpkt` で通信統計を集計するためのプロジェクト。

現在は 1 本の pcap.gz を対象にしたダウンロードと解析を行う。
デフォルトの対象は MAWI DITL 2026 の `202604080000.pcap.gz`。

## セットアップ

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## ダウンロード

```bash
python scripts/download_one.py
```

デフォルトでは次の URL から `data/raw/` へ保存する。

```text
https://mawi.wide.ad.jp/mawi/ditl/ditl2026/202604080000.pcap.gz
```

主なオプション:

- `--url`: ダウンロード対象 URL
- `--outdir`: 保存先ディレクトリ。相対パスはリポジトリルート基準で解決される。デフォルトは `data/raw`
- `--force`: 既存ファイルがある場合も上書きダウンロードする

## 解析

```bash
python scripts/analyze_one.py
```

デフォルトでは `data/raw/202604080000.pcap.gz` を読み込み、
`results/json/202604080000.json` へ解析結果を書き出す。

主なオプション:

- `--input`: 入力する `.pcap.gz` ファイル。デフォルトは `data/raw/202604080000.pcap.gz`
- `--outdir`: JSON 出力先ディレクトリ。相対パスはリポジトリルート基準で解決される
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

- `non_ip`, `ipv4`, `ipv6`

- `tcp`, `udp`, `icmp`, `arp`

上位集計:

- `top_destination_ports`: 宛先ポート上位 20 件。各要素は `{ "port": number, "packets": number }`

- `top_source_ports`: 送信元ポート上位 20 件。各要素は `{ "port": number, "packets": number }`

- `top_source_ips`: 送信元 IP 上位 20 件。各要素は `{ "ip": string, "packets": number }`

- `top_destination_ips`: 宛先 IP 上位 20 件。各要素は `{ "ip": string, "packets": number }`

- `top_source_endpoints`: 送信元 `IP:port` 上位 20 件。各要素は `{ "endpoint": string, "packets": number }`

- `top_destination_endpoints`: 宛先 `IP:port` 上位 20 件。各要素は `{ "endpoint": string, "packets": number }`

- `top_flows`: `PROTO src_ip:src_port -> dst_ip:dst_port` 形式のフロー上位 20 件。各要素は `{ "flow": string, "packets": number }`

- `layer4_protocols`: L4 プロトコル別件数。各要素は `{ "protocol": string, "packets": number }`

- `packets_per_minute_top20`: 分単位のパケット数上位 20 件。各要素は `{ "minute": "YYYY-MM-DD HH:MM", "packets": number }`

## ディレクトリ

- `scripts/`: ダウンロード・解析スクリプト
- `data/raw/`: ダウンロードした pcap.gz の保存先
- `results/json/`: 解析結果 JSON の保存先
- `config/`: 設定ファイル用ディレクトリ
- `state/`: 処理状態管理用ディレクトリ

## 方針

- pcap.gz は gzip 圧縮のまま逐次読み込みする
- 巨大な pcap.gz や解析結果は Git 管理しない
