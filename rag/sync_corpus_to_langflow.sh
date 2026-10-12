#!/bin/sh
# LangFlow Desktop's Directory component may only read inside the server's working
# directory (~/.langflow/data); paths outside it fail with "Directory path escapes the
# allowed root", and symlinks are blocked. Copy the corpus there. Re-run after editing rag/corpus/.
set -e
SRC="$(cd "$(dirname "$0")" && pwd)/corpus"
DST="$HOME/.langflow/data/agentauthz_corpus"
mkdir -p "$DST"
rm -f "$DST"/*.md
cp "$SRC"/*.md "$DST"/
echo "Synced $(ls "$DST"/*.md | wc -l | tr -d ' ') files -> $DST"
