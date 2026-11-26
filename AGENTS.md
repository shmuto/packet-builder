# packet-builder 開発ルール

## 概要

- パケットを組み立てる学習用の Web アプリです。
- GitHub Pages で公開します。サーバー側の処理はありません。
- 構成は Vite + React + TypeScript + Vitest です。

## 完了の条件

- `npm run check` が成功すること。型チェック・テスト・ビルドをまとめて実行します。
- 新しいレイヤーやフィールドを追加する場合は、必ず `src/core/fieldDocs.ts` の `FIELD_DOCS` に RFC / IEEE のセクション番号付きの説明を追加すること。
