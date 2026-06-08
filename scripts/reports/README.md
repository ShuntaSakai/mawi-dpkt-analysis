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
- `--embed-images`: PNG を base64 として HTML に埋め込みます。これは既定動作です。
- `--no-embed-images`: PNG を HTML からの相対パス参照にします。
- `--strict`: 欠損 plot directory や期待 PNG の欠損をエラーにします。

既定では Google Drive などで HTML 単体を共有しやすいように、PNG を base64 data URI として HTML に埋め込みます。HTML ファイルサイズを小さくしたい場合は `--no-embed-images` を指定してください。

生成 HTML には印刷用 CSS を含めています。ブラウザから PDF 保存する場合は A4 横向きを想定し、prefix ごとのセクションが新しいページから始まるように改ページされます。
