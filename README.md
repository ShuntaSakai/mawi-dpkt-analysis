# mawi-dpkt-analysis

MAWIの24-hour-long tracesを対象に、dpktを用いて逐次解析するためのプロジェクト。

## 方針
- まずは1本のpcap.gzを対象に性能確認
- 問題なければ24時間分へ拡張
- gzip圧縮のまま逐次読み込み
- 巨大ファイルはGit管理しない

## ディレクトリ
- scripts/: 解析スクリプト
- data/raw/: ダウンロードしたpcap.gz
- results/: 集計結果
- logs/: 実行ログ
