# packet-builder (tsumiki) 開発ルール

## 概要

- BGP メッセージの中身をパケットキャプチャを開く前に学ぶための学習用 Web アプリです。
- GitHub Pages で公開します。サーバー側の処理はありません（旧汎用パケットビルダーは `/legacy/` に残します）。
- 構成は Vite + React + TypeScript + Vitest です。

## 完了の条件

- `npm run check` が成功すること。型チェック・テスト・ビルドをまとめて実行します。
- CI の `e2e` ジョブ（`npm run e2e`）および `wireshark-oracle` ジョブ（`npm run oracle`）が成功すること。
- BGP ディセクションツリー（`DissectionNode`）のすべてのノードに、学習者向けの平易な説明（`explanation`）と RFC セクション番号付きの参照（`reference`）を必ず含めること。
