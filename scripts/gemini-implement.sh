#!/usr/bin/env bash
# 使い方: scripts/gemini-implement.sh <Issue番号>
#
# Issue の内容を Antigravity CLI（agy）に渡して実装させ、
# テストが通ったら PR を作る。PR ができると Claude のレビューが自動で走る。
#
# agy にはファイルの編集だけを任せる。
# git の操作・テスト・PR 作成は、このスクリプト自身が行う。
#
# 環境変数 AGY_FLAGS で agy に追加の引数を渡せる。
#   例: AGY_FLAGS="--model gemini-3.1-pro" scripts/gemini-implement.sh 1
set -euo pipefail

if [[ $# -ne 1 || ! "$1" =~ ^[0-9]+$ ]]; then
  echo "使い方: $0 <Issue番号>" >&2
  exit 1
fi
issue="$1"

for cmd in gh agy git npm; do
  command -v "$cmd" >/dev/null || { echo "$cmd が見つかりません" >&2; exit 1; }
done

if [[ -n "$(git status --porcelain)" ]]; then
  echo "未コミットの変更があります。片付けてから実行してください。" >&2
  exit 1
fi

title="$(gh issue view "$issue" --json title --jq .title)"
body="$(gh issue view "$issue" --json body --jq .body)"
branch="gemini/issue-${issue}"

git fetch origin main
git switch -c "$branch" origin/main

prompt="$(cat <<PROMPT
GitHub の Issue #${issue} を実装してください。

# Issue のタイトル
${title}

# Issue の本文
${body}

# 守ること
- AGENTS.md のルールに従ってください。
- 実装が終わったら npm run check を実行し、成功するまで直してください。
- git の commit・push・ブランチ操作はしないでください。このあと人間側で行います。
- 最後に、変更内容の要約を日本語で 5 行以内で出力してください。
PROMPT
)"

echo "== agy で実装中: #${issue} ${title}"
# shellcheck disable=SC2086
summary="$(agy -p "$prompt" ${AGY_FLAGS:-})"
echo "$summary"

echo "== 確認: npm run check"
if ! npm run check; then
  echo "チェックが失敗しました。ブランチ ${branch} に変更を残したまま止めます。" >&2
  exit 1
fi

if [[ -z "$(git status --porcelain)" ]]; then
  echo "変更がありませんでした。agy の出力を確認してください。" >&2
  exit 1
fi

git add -A
git commit -m "${title} (#${issue})"
git push -u origin "$branch"

gh pr create \
  --base main \
  --head "$branch" \
  --title "${title}" \
  --body "$(printf 'Closes #%s\n\n## 実装担当（Gemini）による要約\n\n%s\n' "$issue" "$summary")"
