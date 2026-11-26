#!/usr/bin/env bash
# Runs the schema security tests against a throwaway database.
# Usage: PGHOST=... PGPORT=... PGUSER=postgres supabase/tests/run.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
db="posture_test_$$"
createdb "$db"
trap 'dropdb --if-exists "$db"' EXIT
psql -q -v ON_ERROR_STOP=1 -d "$db" -f "$here/auth_stub.sql" >/dev/null
for f in "$here"/../migrations/*.sql; do psql -q -v ON_ERROR_STOP=1 -d "$db" -f "$f" >/dev/null; done
out="$(psql -v ON_ERROR_STOP=1 -d "$db" -f "$here/rls_test.sql")"
echo "$out"
# Ask the database how many tests passed and failed, rather than searching the printed output: a search that stops early
# can break the pipe and report a failure when everything passed. No tests at all also counts as a failure.
verdict="$(psql -v ON_ERROR_STOP=1 -d "$db" -tAc "select count(*) filter (where ok) > 0 and count(*) filter (where not ok) = 0 from test.results")"
[ "$verdict" = "t" ] || { echo "SECURITY TESTS FAILED"; exit 1; }
