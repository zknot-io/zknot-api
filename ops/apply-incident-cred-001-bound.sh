#!/usr/bin/env bash
# apply-incident-cred-001-bound.sh — write the R-2 position bound, once.
#
# INCIDENT-CRED-001 R-2, Option B. Ruled by the operator 2026-09-05; bound
# DECLARED by the operator as chain `default`, position 51.
#
# WHAT IT DOES
#   Sets bound_chain_id / bound_position / bound_reason on the ONE leaked
#   registry key, inside a transaction that then checks its own work and ROLLS
#   BACK on any mismatch. Its failure mode is "refused", never "silently wrong".
#
# WHY THE VALUE IS TYPED HERE AND NOT COMPUTED
#   CLAUDE.md: an expected value is DECLARED by a human before the operation,
#   never COMPUTED from the operation. A bound derived by a query over the
#   records it governs always agrees with itself, which is the one thing a
#   guard exists to prevent. 51 is typed below because a human typed it.
#
# MEASURED BEFORE DECLARING (read-only, 2026-09-05):
#   key id 2  added 2026-07-16, 10 records, chain `default` positions 41-51,
#             all signed 2026-06-29 — nothing since, so the last legitimate
#             position is unambiguous
#   key id 11 added 2026-08-11 (the rotation), 25 records, positions 70-94
#   clean gap at 52-69; chain head 96
#
# SECRET HANDLING is OPS/scripts/zknot-db-read.sh's, which is INCIDENT-CRED-001
# §6's: a real JSON parser, a private file under umask 077, never argv, never a
# terminal. This incident was caused by a secret read; its remedy must not
# repeat the cause.
#
# EXIT
#   0  applied and verified, or already applied with the same values
#   2  refused — bad usage, or the plan was not confirmed
#   3  could not obtain credentials or reach the database
#   4  applied nothing — a self-check failed and the transaction rolled back
set -euo pipefail

# ---- DECLARED VALUES. Change these only with a ruling. ---------------------
KEY_ID=2
BOUND_CHAIN='default'
BOUND_POSITION=51
BOUND_REASON='INCIDENT-CRED-001 R-2 Option B, ruled 2026-09-05. Key printed into a session transcript 2026-08-01 and rotated the same day; the anchor survived the rotation. Bounded to the last position it legitimately signed.'
EXPECT_AT_OR_BELOW=10      # records this key signed, all at or below the bound
EXPECT_ABOVE=0             # records above it — must be zero, or the bound is wrong
# ---------------------------------------------------------------------------

[ -f alembic.ini ] || { echo "run this from the zknot-api checkout root" >&2; exit 2; }

if [ "${1:-}" != "--confirm" ]; then
  cat >&2 <<EOF
This WRITES to zknot-api production.

  key id            $KEY_ID  (the key leaked 2026-08-01)
  bound_chain_id    $BOUND_CHAIN
  bound_position    $BOUND_POSITION

After this, that key anchors ONLY for records at or below position
$BOUND_POSITION on chain '$BOUND_CHAIN'. A record signed with it anywhere else, or
above that position, stops verifying — which is the point.

Self-checks inside the same transaction, all must hold or it rolls back:
  - exactly ONE trusted_keys row is bounded
  - that row is key id $KEY_ID, chain '$BOUND_CHAIN', position $BOUND_POSITION
  - records signed by it at or below the bound == $EXPECT_AT_OR_BELOW
  - records signed by it above the bound      == $EXPECT_ABOVE

Re-run with --confirm to apply.
EOF
  exit 2
fi

command -v railway >/dev/null || { echo "railway CLI not found" >&2; exit 3; }
command -v psql   >/dev/null || { echo "psql not found" >&2; exit 3; }

TMP="$(mktemp -d)"; chmod 700 "$TMP"
trap 'rm -rf "$TMP"' EXIT INT TERM

( umask 077; railway variables --service Postgres --json > "$TMP/vars.json" 2>"$TMP/err" ) || {
  echo "could not read Railway variables:" >&2; head -3 "$TMP/err" >&2 || true; exit 3; }

( umask 077; python3 - "$TMP/vars.json" > "$TMP/dbenv" <<'PY'
import json, sys, urllib.parse as up
data = json.load(open(sys.argv[1]))
url = data.get("DATABASE_PUBLIC_URL")
if not url:
    sys.exit("DATABASE_PUBLIC_URL not present on service Postgres")
u = up.urlparse(url)
print(f"PGHOST={u.hostname}")
print(f"PGPORT={u.port or 5432}")
print(f"PGUSER={up.unquote(u.username or '')}")
print(f"PGPASSWORD={up.unquote(u.password or '')}")
print(f"PGDATABASE={(u.path or '/postgres').lstrip('/')}")
PY
) || exit 3

set -a; . "$TMP/dbenv"; set +a

# The normalisation here MUST match app/services/trust_anchor.py: lowercase,
# strip an 0x prefix, strip a SEC1 04 prefix on a 65-byte key. A whitespace-only
# compare misses a re-encoded key and would undercount the records.
psql -v ON_ERROR_STOP=1 -q -X -A -F'|' \
     -v key_id="$KEY_ID" -v bchain="$BOUND_CHAIN" -v bpos="$BOUND_POSITION" \
     -v breason="$BOUND_REASON" \
     -v exp_below="$EXPECT_AT_OR_BELOW" -v exp_above="$EXPECT_ABOVE" \
     <<'SQL' > "$TMP/out" 2>"$TMP/sqlerr" || { echo "psql failed:" >&2; head -20 "$TMP/sqlerr" >&2; exit 4; }
\set ON_ERROR_STOP on
BEGIN;

-- psql interpolates a colon-variable in ordinary SQL, but NOT inside a
-- dollar-quoted body: that text reaches the server verbatim, and the server has
-- no idea what a leading colon means. Measured 2026-09-05 against production --
-- it failed with `syntax error at or near ":"` and the transaction rolled back,
-- writing nothing. Values reach the DO block as transaction-local settings
-- instead, which survive into it because they live in the session, not the text.
-- Keep this comment free of both, so a grep for either finds only real code.
SET LOCAL zk.key_id    = :'key_id';
SET LOCAL zk.bchain    = :'bchain';
SET LOCAL zk.bpos      = :'bpos';
SET LOCAL zk.exp_below = :'exp_below';
SET LOCAL zk.exp_above = :'exp_above';

UPDATE trusted_keys
   SET bound_chain_id = :'bchain',
       bound_position = :'bpos'::int,
       bound_reason   = :'breason'
 WHERE id = :'key_id'::int;

-- ---- self-checks. Any failure raises, which rolls the whole thing back. ----
DO $$
DECLARE
  k_id      int  := current_setting('zk.key_id')::int;
  b_chain   text := current_setting('zk.bchain');
  b_pos     int  := current_setting('zk.bpos')::int;
  exp_below int  := current_setting('zk.exp_below')::int;
  exp_above int  := current_setting('zk.exp_above')::int;
  n_bounded int; n_below int; n_above int; got_chain text; got_pos int;
BEGIN
  SELECT count(*) INTO n_bounded FROM trusted_keys WHERE bound_position IS NOT NULL;
  IF n_bounded <> 1 THEN
    RAISE EXCEPTION 'expected exactly 1 bounded key, found %', n_bounded;
  END IF;

  SELECT bound_chain_id, bound_position INTO got_chain, got_pos
    FROM trusted_keys WHERE id = k_id;
  IF got_chain IS DISTINCT FROM b_chain OR got_pos IS DISTINCT FROM b_pos THEN
    RAISE EXCEPTION 'bound did not land: chain=% pos=%', got_chain, got_pos;
  END IF;

  WITH norm AS (
    SELECT a.artifact_id,
      CASE WHEN length(regexp_replace(lower(btrim(a.public_key)),'^0x','')) = 130
            AND left(regexp_replace(lower(btrim(a.public_key)),'^0x',''),2) = '04'
           THEN substr(regexp_replace(lower(btrim(a.public_key)),'^0x',''),3)
           ELSE regexp_replace(lower(btrim(a.public_key)),'^0x','') END AS k
    FROM artifacts a)
  SELECT
    count(*) FILTER (WHERE ce.chain_id = b_chain AND ce.position <= b_pos),
    count(*) FILTER (WHERE ce.chain_id <> b_chain OR  ce.position >  b_pos)
  INTO n_below, n_above
  FROM norm n
  JOIN chain_entries ce ON ce.artifact_id = n.artifact_id
  JOIN trusted_keys tk  ON lower(tk.public_key_norm) = n.k
  WHERE tk.id = k_id;

  IF n_below <> exp_below THEN
    RAISE EXCEPTION 'records at or below the bound: expected %, got %',
      exp_below, n_below;
  END IF;
  IF n_above <> exp_above THEN
    RAISE EXCEPTION 'records ABOVE the bound: expected %, got % -- a published record would stop verifying. Refusing.',
      exp_above, n_above;
  END IF;

  RAISE NOTICE 'verified: 1 bounded key, % records at or below the bound, % above', n_below, n_above;
END $$;

COMMIT;

SELECT id, label, product, active, bound_chain_id, bound_position
  FROM trusted_keys WHERE product = 'registry' ORDER BY id;
SQL

echo "applied and verified:"
cat "$TMP/out"
grep -i 'NOTICE' "$TMP/sqlerr" 2>/dev/null || true
