# packet-builder

画面上の名前は tsumiki（積み木）です。

パケットを組み立てる学習用の Web アプリです。

実装は Gemini（Antigravity CLI）が書き、レビューは Claude Opus が自動で行う、という分担を試すためのリポジトリでもあります。

## 開発

```bash
npm install
npm run dev      # 開発サーバー
npm run check    # 型チェック・テスト・ビルド
```

## 初回セットアップ

1. GitHub に空のリポジトリを作り、このフォルダを push する。
2. リポジトリの Settings → Pages で、Source を「GitHub Actions」にする。
3. Claude GitHub App（https://github.com/apps/claude）をこのリポジトリにインストールする。
4. 手元で `claude setup-token` を実行し、出てきたトークンをリポジトリのシークレット `CLAUDE_CODE_OAUTH_TOKEN` に登録する。
5. 手元で `agy` を一度起動し、Google AI Pro / Ultra のアカウントでログインしておく。

## 1 つの Issue を進める流れ

```bash
scripts/gemini-implement.sh 1
```

1. Issue #1 の内容を agy に渡して実装させる。
2. `npm run check` が通ったら、コミットして push し、PR を作る。
3. PR ができると、Claude のレビューが自動で走る。
4. 指摘を直すときは、同じブランチで agy に修正を頼んで push する。再レビューが自動で走る。

## agy の権限について

`agy -p` は、承認が必要な操作を自動で拒否して処理を続けます。
ファイルの編集や `npm` の実行が拒否される場合は、`~/.gemini/antigravity-cli/settings.json` の `permissions.allow` に必要な操作を追加してください。

## ワークフロー

| ファイル | 役割 |
| --- | --- |
| `.github/workflows/ci.yml` | PR と main への push で `npm run check` を実行 |
| `.github/workflows/claude-review.yml` | PR の作成・更新時に Claude Opus がレビュー |
| `.github/workflows/pages.yml` | main への push で GitHub Pages に公開 |
