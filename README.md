# packet-builder

画面上の名前は tsumiki（積み木）です。

Ethernet II / IPv4 / ICMP / UDP / TCP のレイヤーを積み木のように重ねて、パケットを組み立てる学習用の Web アプリです。

実装は Gemini（Antigravity）が書き、レビューは Claude Opus が自動で行う、という分担を試すためのリポジトリでもあります。

## 実装状況

- [x] **Step 1**: バイト列ユーティリティ・RFC 1071 チェックサム・IPv4 擬似ヘッダチェックサム
- [x] **Step 2**: プロトコルエンコーダ一式（Ethernet II / IPv4 / ICMP / UDP / TCP）とビット範囲マップ
- [ ] **Step 3**: 積み木レイヤーエディタ UI & ライブ 16 進ダンプ（プリセット・自動/手動切替・エラー/警告表示）
- [ ] **Step 4**: フィールド⇔バイト双方向ハイライト・32-bit ビット図・Hex コピー＆PCAP ダウンロード

## 構成

- `src/core/`：パケット組み立てロジック（React / DOM 非依存、同階層に `*.test.ts` を配置）
  - `result.ts`：例外を投げずに成功・エラーを返す `Result<T>` 型と `ok` / `err` ヘルパー
  - `bytes.ts`：MAC / IPv4 / Hex 文字列のパース、UTF-8 変換、ビッグエンディアン書き込み、16 進ダンプ整形
  - `checksum.ts`：RFC 1071 インターネットチェックサム・IPv4 擬似ヘッダチェックサム
  - `layers/`：Ethernet II / IPv4 / ICMP / UDP / TCP の型定義とエンコーダ
  - `packet.ts`：レイヤー配列とペイロードからパケット全体とビット範囲マップ（`FieldSpan[]`）を生成する `buildPacket`
  - `presets.ts`：初期プリセット（UDP / TCP SYN / ICMP Ping）
- `src/ui/`：React コンポーネント（`src/core/` の関数を呼び出して表示のみを担当。Step 3 で追加予定）

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

## 開発の流れ

1. 作業用ブランチを切り、実装して `npm run check` を通す。
2. コミット・push して PR を作成する。
3. PR の作成・更新時に CI（`npm run check`）と Claude Opus の自動レビューが走る。
4. レビュー指摘を同じブランチで修正して push し、確認後に `main` へマージする（マージで GitHub Pages に自動公開される）。

## ワークフロー

| ファイル | 役割 |
| --- | --- |
| `.github/workflows/ci.yml` | PR と main への push で `npm run check` を実行 |
| `.github/workflows/claude-review.yml` | PR の作成・更新時に Claude Opus がレビュー |
| `.github/workflows/pages.yml` | main への push で GitHub Pages に公開 |
