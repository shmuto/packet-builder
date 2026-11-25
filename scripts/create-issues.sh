#!/usr/bin/env bash
# docs/issues/*.md から GitHub の Issue を作る。
# 各ファイルの 1 行目（"# " で始まる行）をタイトル、2 行目以降を本文にする。
set -euo pipefail

for file in docs/issues/*.md; do
  title="$(head -n 1 "$file" | sed 's/^# //')"
  tail -n +2 "$file" | gh issue create --title "$title" --body-file -
done
