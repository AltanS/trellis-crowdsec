#!/usr/bin/env bash
set -euo pipefail

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

# Only run lint on git commit commands
if ! echo "$COMMAND" | grep -q '^git commit'; then
  exit 0
fi

cd "$(git rev-parse --show-toplevel)"
uv run ansible-lint
