#!/bin/bash
# MCP Security Audit action entry. Builds one CodeQL DB and runs the MCP-aware
# taint queries. NO_SOURCE (nothing to scan) is an explicit verdict, never a
# silent pass - the false-green class this repo exists to avoid.
set -euo pipefail
SRC="${1:-.}"; FAIL_ON="${2:-true}"
PACK="$(cd "$(dirname "$0")/../codeql/mcp-js" && pwd)"
emit() { echo "$1=$2" >> "${GITHUB_OUTPUT:-/dev/stdout}"; }

if ! command -v codeql >/dev/null 2>&1; then echo "::error::codeql not found on PATH"; exit 1; fi
if [ -z "$(find "$SRC" -name '*.js' -o -name '*.ts' -o -name '*.cjs' -o -name '*.mjs' 2>/dev/null | head -1)" ]; then
  emit verdict NO_SOURCE; emit path 0; emit cmd 0; emit sql 0
  echo "::warning::no JavaScript/TypeScript source under $SRC - nothing scanned"; exit 0
fi
DB="$(mktemp -d)/db"
codeql database create "$DB" --language=javascript --source-root="$SRC" --overwrite >/dev/null
runq() { local out; out="$(mktemp).bqrs"; codeql query run --database="$DB" --output="$out" "$PACK/$1" >/dev/null 2>&1 || true; codeql bqrs info "$out" 2>/dev/null | grep -oE '#select has [0-9]+' | grep -oE '[0-9]+' || echo 0; }
P=$(runq McpPathTraversalJs.ql); C=$(runq McpCommandInjectionJs.ql); S=$(runq McpSqlInjectionJs.ql)
TOTAL=$((P + C + S))
if [ "$TOTAL" -gt 0 ]; then V=FINDINGS; else V=CLEAN; fi
emit verdict "$V"; emit path "$P"; emit cmd "$C"; emit sql "$S"
echo "MCP Security Audit: $V (path=$P cmd=$C sql=$S)"
if [ "$V" = "FINDINGS" ] && [ "$FAIL_ON" = "true" ]; then echo "::error::MCP taint flows found"; exit 1; fi
