# packet-builder

画面上の名前は tsumiki（積み木）です。

Ethernet / IPv4 / UDP のレイヤーを積み木のように重ねて、パケットを組み立てる学習用の Web アプリです。

実装は Gemini（Antigravity CLI）が書き、レビューは Claude Opus が自動で行う、という分担を試すためのリポジトリでもあります。

## 実装状況

- [x] バイト列の基本関数とチェックサム（`parseMac` / `parseIPv4` / `internetChecksum` / `toHexDump`）
- [ ] Ethernet / IPv4 / UDP ヘッダの組み立て（`buildPacket`）
- [ ] レイヤー編集画面（入力フォーム・自動/手動切替・16 進ダンプ表示）
- [ ] フィールドとバイトの対応強調表示・16 進文字列コピー

各タスクの詳細は `docs/issues/` を参照してください。

## 構成

- `src/core/`：パケット組み立てロジック（React / DOM 非依存、同階層に `*.test.ts` を配置）
  - `result.ts`：例外を投げずに成功・エラーを返す `Result<T>` 型とヘルパー
  - `bytes.ts`：MAC / IPv4 アドレスのパース（`parseMac`, `parseIPv4`）と 16 進ダンプ生成（`toHexDump`）
  - `checksum.ts`：RFC 1071 インターネットチェックサム（`internetChecksum`）
- `src/ui/`：React コンポーネント（`src/core/` の関数を呼び出して表示のみを担当）
- `docs/issues/`：各 Issue の仕様書

## 開発

```bash
npm install
npm run dev        # 開発サーバー
npm run test       # ユニットテスト（Vitest）
npm run typecheck  # 型チェック（tsc --noEmit）
npm run check      # 型チェック・テスト・ビルドを一括実行
```

## GitHub 側のセットアップ

1. リポジトリの Settings → Pages で、Source を「GitHub Actions」にする。
2. Claude GitHub App（https://github.com/apps/claude）をこのリポジトリにインストールする。
3. `claude setup-token` で発行したトークンを、リポジトリのシークレット `CLAUDE_CODE_OAUTH_TOKEN` に登録する。

## 1 つの Issue を進める流れ

1. `docs/issues/` の仕様に沿ってブランチを切り、実装して `npm run check` を通す。
2. コミット・push して PR を作成する（1 PR = 1 Issue）。
3. PR の作成・更新時に CI（`npm run check`）と Claude Opus の自動レビューが走る。
4. レビュー指摘を同じブランチで修正して push し、確認後に `main` へマージする（マージで GitHub Pages に自動公開される）。

## ワークフロー

| ファイル | 役割 |
| --- | --- |
| `.github/workflows/ci.yml` | PR と main への push で `npm run check` を実行 |
| `.github/workflows/claude-review.yml` | PR の作成・更新時に Claude Opus がレビュー |
| `.github/workflows/pages.yml` | main への push で GitHub Pages に公開 |
