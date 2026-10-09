#!/usr/bin/env bash
# 画像を作る。依存は uv.lock からハッシュ付きで書き出し、本体は手元で作った wheel を入れる。
#
#   tools/image-build.sh [TAG]      既定の TAG は pyproject.toml の version
set -euo pipefail
cd "$(dirname "$0")/.."
tag="${1:-$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')}"
uv export --frozen --no-dev --no-emit-project -o deploy/requirements.txt >/dev/null
rm -rf deploy/dist
uv build --wheel -o deploy/dist >/dev/null
docker build -t "llm-incident-analyst:${tag}" .
docker image inspect "llm-incident-analyst:${tag}" --format '画像 {{index .RepoTags 0}} {{.Size}} バイト {{.Id}}'
