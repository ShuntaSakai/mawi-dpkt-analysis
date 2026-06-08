# scripts/reports/

`scripts/reports/` には、既存の解析・可視化結果を読み取り、研究用レポートとしてまとめる後段スクリプトを配置します。

## HTML report

`generate_analysis_report.py` は `results/comparison/<dataset>/comparison_summary.csv` と `results/comparison/<dataset>/plots/` 配下の PNG を読み、`results/reports/<dataset>/analysis_report.html` を生成します。

```bash
python scripts/reports/generate_analysis_report.py --dataset 202604081300
```

主なオプション:

- `--prefix <target>`: 指定した prefix だけを出力します。複数回指定できます。
- `--features duration packet_count`: 表示する feature 画像を絞ります。
- `--no-histograms`: `histograms/` 配下の画像を除外します。
- `--embed-images`: PNG を base64 として HTML に埋め込みます。
- `--strict`: 欠損 plot directory や期待 PNG の欠損をエラーにします。

既定では画像を相対パス参照にし、HTML ファイルサイズの巨大化を避けます。
