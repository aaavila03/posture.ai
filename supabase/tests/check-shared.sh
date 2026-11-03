#!/usr/bin/env bash
# The AI task definitions must be identical in the browser and the server function.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
for f in ai-tasks.js intake-questions.js; do
  if ! cmp -s "$root/$f" "$root/supabase/functions/_shared/$f"; then
    echo "supabase/functions/_shared/$f is out of date. Run:"
    echo "  cp $f supabase/functions/_shared/$f"
    exit 1
  fi
  echo "$f in sync"
done
