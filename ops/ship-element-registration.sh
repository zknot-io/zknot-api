#!/usr/bin/env bash
# ship-element-registration.sh — take DECISION-ELEMENT-REGISTRATION-001 live, in the one
# safe order: migrate production FIRST (0013 + 0014), THEN fast-forward main (Railway
# deploys on push and never runs migrations), THEN probe the live API.
#
# Run from ~/zknot-api. Stops at the first thing that is not as expected.
#   0  live and probed
#   1  a precondition or probe failed — read the message, nothing after it ran
set -euo pipefail

BRANCH=feat/element-registration
EXPECT_MAIN=23fc703          # origin/main when the branch was cut, 2026-10-16
API=https://api.zknot.io
KNOWN_CODE=ZK-SW8B-E9Y       # WM-0002, a live record that must still verify

die() { echo "STOP: $*" >&2; exit 1; }
[ -f alembic.ini ] || die "run from the zknot-api checkout root"
[ -z "$(git status --porcelain --untracked-files=no)" ] || die "working tree has uncommitted changes"

echo "== 1/5 refs"
git fetch -q origin
main_now=$(git rev-parse --short=7 origin/main)
[ "$main_now" = "$EXPECT_MAIN" ] || die "origin/main moved to $main_now (expected $EXPECT_MAIN). Someone else shipped; rebase-free rule: stop and look."
git merge-base --is-ancestor origin/main "origin/$BRANCH" || die "$BRANCH does not fast-forward from main"
echo "   main $main_now, $BRANCH $(git rev-parse --short=7 origin/$BRANCH): fast-forward OK"

echo "== 2/5 tests on the branch"
git switch -q "$BRANCH"
git merge -q --ff-only "origin/$BRANCH"
python3 -m pytest -q -p no:warnings tests/test_element_registration.py tests/test_schema_guard.py \
  || die "tests failed on the branch"

echo "== 3/5 migrate production to 0014 (0013 runs with it; migrate.sh shows the plan and asks)"
ops/migrate.sh 0014_element_key_uniqueness

echo "== 4/5 fast-forward main and push (Railway deploys this)"
git switch -q main
git merge -q --ff-only "origin/$BRANCH"
git push -q origin main
echo "   pushed main $(git rev-parse --short=7 HEAD)"

echo "== 5/5 probe live (waiting for the deploy, up to ~6 min)"
for i in $(seq 1 36); do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/v1/elements/challenge" || true)
  # 401 = the new route exists and wants the token. 404 = old build still serving.
  if [ "$code" = "401" ]; then echo "   /v1/elements/challenge -> 401 (new build live)"; break; fi
  sleep 10
done
[ "${code:-}" = "401" ] || die "new route never appeared (last $code). Check the Railway deploy log; if it is red, the schema guard refused — check alembic_version."

body=$(curl -s "$API/v1/verify/$KNOWN_CODE")
python3 - "$body" <<'PY' || exit 1
import json, sys
d = json.loads(sys.argv[1])
ok = d.get("verified") is True and d.get("chain_integrity") is True and "manufacturer_certificate_valid" in d
print(f"   {d.get('short_code')}: verified={d.get('verified')} chain_integrity={d.get('chain_integrity')} "
      f"manufacturer_certificate_valid={d.get('manufacturer_certificate_valid')}")
if not ok:
    print("STOP: existing record no longer verifies cleanly on the new build", file=sys.stderr)
    raise SystemExit(1)
PY
echo "DONE: element registration is live. Next: verifier.js wording, then the jig station client."
