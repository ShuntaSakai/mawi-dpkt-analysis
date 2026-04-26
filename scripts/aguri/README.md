# scripts/aguri/

`scripts/aguri/` は、`aguri3` / `agurim` を使って MAWI キャプチャから prefix 候補を抽出するためのディレクトリです。ここで得られるのはあくまで候補であり、最終的な選定は [../prefix/evaluate_prefixes.py](../prefix/evaluate_prefixes.py) で flow 特徴量に基づいて行います。

## 使い方

### 1. aguri3 / agurim を実行して中間成果物を作る

- スクリプト: `run_aguri.py`
- 必須オプション:
  - `--pcap`
- 主なデフォルト:
  - `--dataset` 未指定時: 入力ファイル名から推定
  - 出力先未指定時: `results/aguri/<dataset>/`
  - `aguri3` 実行ファイル:
    - `scripts/aguri/agurim/src/aguri3` があればそれを使用
    - なければ `PATH` 上の `aguri3` を使用
  - `agurim` 実行ファイル:
    - `scripts/aguri/agurim/src/agurim` があればそれを使用
    - なければ `PATH` 上の `agurim` を使用
- 最小実行例:

```bash
python scripts/aguri/run_aguri.py \
  --pcap data/raw/http_traffic.pcap.gz
```

### 2. agurim テキストを候補 CSV に変換する

- スクリプト: `parse_agurim.py`
- 必須オプション:
  - `--input`
- 主なデフォルト:
  - 出力先未指定時: `<input_dir>/<dataset>.aguri_candidates.csv`
  - `--strict` 無効時: 解釈できない行は警告を出して継続
- 最小実行例:

```bash
python scripts/aguri/parse_agurim.py \
  --input results/aguri/http_traffic/http_traffic.agurim.txt
```

## パイプライン

```text
pcap.gz / pcap / pcapng / pcapng.gz
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

## 前提

- `run_aguri.py` は `aguri3` と `agurim` が利用可能であることを前提にしています。
- 同梱バイナリが見つからず `PATH` にも存在しない場合はエラーになります。
- リポジトリ同梱版を使う場合のビルド例:

```bash
cd scripts/aguri/agurim/src
make
```

## スクリプト詳細

### `run_aguri.py`

- 役割:
  - 入力キャプチャに対して `aguri3` と `agurim` を順に実行します。
- 入力:
  - `pcap`
  - `pcap.gz`
  - `pcapng`
  - `pcapng.gz`
- 出力:
  - `<dataset>.agr`
  - `<dataset>.agurim.txt`
- デフォルト出力先:
  - `results/aguri/<dataset>/`
- `dataset` 名の決定:
  - `--dataset` 指定時はその値を使用
  - 未指定時は入力ファイル名から拡張子を除いて推定
- 圧縮入力の扱い:
  - `.gz` 入力は一時ディレクトリへ展開してから `aguri3` に渡します。
  - 展開後の拡張子が想定外なら警告が出ます。
- 上書き挙動:
  - 既存の `.agr` または `.agurim.txt` がある場合、`--force` なしでは停止します。
- 主なオプション:
  - `--dataset`
    - 出力ディレクトリ名と出力ファイル名の基準を明示したいときに使います。
  - `--out-dir`
    - 既定の `results/aguri/<dataset>/` 以外へ出したいときに使います。
  - `--aguri3-bin`
    - 独自ビルドや別配置の `aguri3` を使うときに指定します。
  - `--agurim-bin`
    - 独自ビルドや別配置の `agurim` を使うときに指定します。
  - `--force`
    - 既存成果物を上書きしたいときに指定します。
- 実行時の標準出力:
  - 実行コマンド
  - 完了後の `.agr` と `.agurim.txt` の保存先

### `parse_agurim.py`

- 役割:
  - `agurim` のテキスト出力を、後続の prefix 評価で扱いやすい CSV に整形します。
- 入力:
  - `*.agurim.txt`
- 出力:
  - `*.aguri_candidates.csv`
- デフォルト出力先:
  - `<input_dir>/<dataset>.aguri_candidates.csv`
- 解析対象:
  - 集約エントリ本体
  - その下にインデントされて続く protocol breakdown 行
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
- 列の意味:
  - `aggregate_id`
    - agurim 出力中の集約 ID
  - `src_prefix`, `dst_prefix`
    - 集約対象の prefix
  - `bytes`, `packets`
    - カンマ除去後の集約バイト数とパケット数
  - `byte_ratio`, `packet_ratio`
    - agurim 出力に含まれる全体比率
  - `tcp_*`, `udp_*`
    - `protocol_breakdown` 内の protocol 6 / 17 を合算した比率
  - `protocol_breakdown`
    - 元の protocol 詳細文字列
- エラーと警告:
  - 既存出力があり `--force` なしなら停止します。
  - 入力不存在なら停止します。
  - 解釈できない行は、通常は警告として標準エラーに出して処理継続します。
  - `--strict` 指定時は解釈不能行があると失敗します。

## 研究上の位置づけ

- `aguri3` / `agurim` は、通信量ベースで「有意そうな prefix 候補」を抽出する段階です。
- ここで得られた候補をそのまま採用せず、後続の `scripts/prefix/evaluate_prefixes.py` で flow 特徴量から再評価してください。
- 特に、通信量が大きいことだけを根拠に選定しない構成を前提にしています。

## 追加の実行例

### dataset 名を明示して実行する

```bash
python scripts/aguri/run_aguri.py \
  --pcap data/raw/http_traffic.pcap.gz \
  --dataset http_traffic
```

### 出力先を明示して CSV 化する

```bash
python scripts/aguri/parse_agurim.py \
  --input results/aguri/http_traffic/http_traffic.agurim.txt \
  --output results/aguri/http_traffic/http_traffic.aguri_candidates.csv
```

### 解釈不能行をエラーにする

```bash
python scripts/aguri/parse_agurim.py \
  --input results/aguri/http_traffic/http_traffic.agurim.txt \
  --strict
```
