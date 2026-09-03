#!/usr/bin/env bash
# migrate.sh — apply ONE named alembic revision to zknot-api production.
#
# Sibling of ~/ZKNOT/OPS/scripts/zknot-db-read.sh and built to the same rules
# (INCIDENT-CRED-001 §6): the secret store is parsed by a real JSON parser, the
# URL lands in a private file under umask 077, and it reaches alembic only
# through the environment — never argv (visible in `ps`), never stdout.
#
# WHY THIS EXISTS RATHER THAN A ONE-LINER
# ---------------------------------------
# Two traps, both hit for real:
#
#   1. `railway run --service Postgres -- alembic upgrade ...` injects that
#      SERVICE's environment, where DATABASE_URL is postgres.railway.internal —
#      resolvable only inside Railway's network. From a workstation it dies with
#      "could not translate host name". Measured 2026-09-03. The public host is
#      in DATABASE_PUBLIC_URL, which is what this uses.
#
#   2. alembic/env.py line 18 overwrites sqlalchemy.url with settings.database_url
#      at import, so alembic.ini and Config.set_main_option are both ignored.
#      DATABASE_URL is the ONLY handle on where a migration connects.
#
# A NAMED REVISION IS REQUIRED. `head` is refused on purpose. 0007's docstring
# records why: it was written while 0004, 0005 and 0006 were still unapplied, and
# "applying this one does not apply the three before it — check what upgrade
# actually intends to run before running it". A bare `head` is how you apply
# three migrations you had not read.
#
# USAGE
#   ops/migrate.sh 0009_tree_observation_type
#
# EXIT
#   0  applied (or already at that revision)
#   2  refused — bad usage, or the plan was not confirmed
#   3  could not obtain credentials or reach the database
set -euo pipefail

TARGET="${1:-}"
case "$TARGET" in
  "")     echo "usage: ops/migrate.sh <revision>   (e.g. 0009_tree_observation_type)" >&2; exit 2 ;;
  head|heads) echo "refused: name the revision explicitly, not '$TARGET'. See the header." >&2; exit 2 ;;
esac

[ -f alembic.ini ] || { echo "run this from the zknot-api checkout root" >&2; exit 2; }
ls "alembic/versions/${TARGET}.py" >/dev/null 2>&1 \
  || { echo "no such migration file: alembic/versions/${TARGET}.py" >&2; exit 2; }

command -v railway >/dev/null || { echo "railway CLI not found" >&2; exit 3; }

TMP="$(mktemp -d)"; chmod 700 "$TMP"
trap 'rm -rf "$TMP"' EXIT INT TERM

( umask 077; railway variables --service Postgres --json > "$TMP/vars.json" 2>"$TMP/err" ) || {
  echo "could not read Railway variables:" >&2; head -3 "$TMP/err" >&2 || true; exit 3; }

# Real parser, one named key, written straight to a private file.
( umask 077; python3 - "$TMP/vars.json" > "$TMP/dbenv" <<'PY'
import json, sys, urllib.parse as up
data = json.load(open(sys.argv[1]))
url = data.get("DATABASE_PUBLIC_URL")
if not url:
    print("DATABASE_PUBLIC_URL absent from service 'Postgres'", file=sys.stderr)
    raise SystemExit(3)
u = up.urlparse(url)
if not (u.hostname and u.username):
    print("DATABASE_PUBLIC_URL is not a parseable connection URL", file=sys.stderr)
    raise SystemExit(3)
if "railway.internal" in u.hostname:
    print(f"refusing: {u.hostname} is reachable only inside Railway", file=sys.stderr)
    raise SystemExit(3)
print("export DATABASE_URL='%s'" % url.replace("'", "'\\''"))
PY
) || exit 3

set +u; . "$TMP/dbenv"; set -u

echo "— where production is now —"
python3 -m alembic current 2>&1 | grep -vi "^INFO" || true
echo
# Only the revisions that will actually RUN. `alembic history -r current:target`
# includes the current revision as the range start, which reads as though it is
# about to be re-applied — a bad thing to misread immediately before a
# production write.
echo "— what will actually run —"
CUR="$(python3 -m alembic current 2>/dev/null | grep -oE '^[0-9a-z_]+' | head -1)"
python3 - "$CUR" "$TARGET" <<'PY2'
import glob, re, sys
cur, target = sys.argv[1], sys.argv[2]
nxt, title = {}, {}
for f in glob.glob("alembic/versions/*.py"):
    src = open(f).read()
    r = re.search(r'^revision\s*=\s*"([^"]+)"', src, re.M)
    d = re.search(r'^down_revision\s*=\s*(?:"([^"]+)"|None)', src, re.M)
    if not r:
        continue
    nxt[d.group(1) if d and d.group(1) else None] = r.group(1)
    title[r.group(1)] = (src.split('"""', 2)[1].strip().splitlines() or [""])[0]
steps, node = [], cur
while node in nxt:
    node = nxt[node]
    steps.append(node)
    if node == target:
        break
if not steps:
    print("  nothing — already at or past this revision")
else:
    for s_ in steps:
        print(f"  {s_}   {title.get(s_,'')}")
    if steps[-1] != target:
        print(f"  WARNING: chain does not reach {target}")
    if len(steps) > 1:
        print(f"  NOTE: {len(steps)} migrations, not one. Read every one before confirming.")
PY2
echo
printf "apply %s to PRODUCTION? type the revision to confirm: " "$TARGET"
read -r CONFIRM
[ "$CONFIRM" = "$TARGET" ] || { echo "not confirmed — nothing applied" >&2; exit 2; }

python3 -m alembic upgrade "$TARGET"

echo
echo "— where production is now —"
python3 -m alembic current 2>&1 | grep -vi "^INFO" || true
