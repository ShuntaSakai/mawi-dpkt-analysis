# notebooks/

このディレクトリには、既存 pipeline が `results/` 配下に出力した CSV、JSON、画像を確認・図化するための Jupyter Notebook を置きます。

- `analysis_results_viewer.ipynb`
  - dataset / target を切り替えながら、prefix 評価、comparison summary、既存 plot、`features.json` の histogram / CDF を確認する探索用 notebook です。
- `paper_report_figures.ipynb`
  - 解析済み `comparison_summary.csv` から、`packet_count_median` / `byte_count_median` / `duration_median` の 3 特徴量比較図だけを PNG / PDF で生成する notebook です。

どちらも元 pcap や大規模 flow CSV の再処理は行わず、`results/` の生成済み summary / plot を読み込みます。実行にはプロジェクトの `requirements.txt` に含まれる `pandas` と `matplotlib` が必要です。
