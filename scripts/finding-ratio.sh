#!/usr/bin/env bash
# Criticals per KLOC, on a real corpus, against a recorded baseline.
#
# The count of findings on its own means nothing. Ten criticals in a thousand
# lines and ten in a hundred thousand are different tools. The ratio is the
# only number that survives a corpus swap, so it is the number worth watching.
#
# Synthetic input is not accepted here. A generated file has a known finding
# count by construction, so measuring against one proves only that the scanner
# reads what it wrote. Point CORPUS at a checkout.
#
#   CORPUS=/path/to/repo ./scripts/finding-ratio.sh
#
# Exits non-zero when the ratio moves off the baseline by more than the
# tolerance, so it can gate a release rather than merely inform one.

set -euo pipefail

CORPUS="${CORPUS:-.}"
BIN="${BIN:-./target/release/heides}"
BASELINE_FILE="${BASELINE_FILE:-$(dirname "$0")/../docs/finding-ratio-baseline.txt}"
# A doubling is a regression; a halving may be a fix or may be blindness, so it
# is reported rather than failed on.
TOLERANCE="${TOLERANCE:-2.0}"

if [ ! -d "$CORPUS" ]; then
  echo "no corpus at $CORPUS. set CORPUS to a real checkout" >&2
  exit 2
fi
if [ ! -x "$BIN" ]; then
  echo "no binary at $BIN. run cargo build --release" >&2
  exit 2
fi

# Counted in python rather than `find | xargs wc -l`: the xargs form splits on
# whitespace and dies on a path with a space in it, which is a corpus-dependent
# way to fail. Python skips anything unreadable instead of aborting the run.
lines=$(CORPUS="$CORPUS" timeout 120 python3 - <<'PY'
import os, sys

EXTS = {
    ".c", ".h", ".cpp", ".hpp", ".cc",
    ".js", ".ts", ".jsx", ".tsx",
    ".py", ".rb", ".go", ".java", ".rs", ".php", ".cs",
}
SKIP = {"node_modules", "target", ".git", ".heides", "vendor", "dist", "build"}
root = os.environ["CORPUS"]
total = 0
for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d not in SKIP]
    for name in filenames:
        if os.path.splitext(name)[1] not in EXTS:
            continue
        try:
            with open(os.path.join(dirpath, name), "rb") as fh:
                total += sum(1 for _ in fh)
        except OSError:
            continue
print(total)
PY
)

if [ -z "${lines:-}" ] || [ "$lines" -eq 0 ]; then
  echo "no source lines under $CORPUS" >&2
  exit 2
fi

summary=$("$BIN" check --no-deps "$CORPUS" 2>&1 | grep -E '^[0-9]+ blocker' | head -1)
critical=$(echo "$summary" | sed -nE 's/.*, ([0-9]+) critical.*/\1/p')
[ -n "$critical" ] || critical=0
blocker=$(echo "$summary" | sed -nE 's/^([0-9]+) blocker.*/\1/p')
[ -n "$blocker" ] || blocker=0

kloc=$(awk -v l="$lines" 'BEGIN{printf "%.1f", l/1000}')
ratio=$(awk -v c="$critical" -v k="$kloc" 'BEGIN{printf "%.2f", (k>0? c/k : 0)}')

echo "corpus   $CORPUS"
echo "lines    $lines ($kloc kloc)"
echo "blockers $blocker"
echo "criticals $critical"
echo "ratio    $ratio criticals per kloc"

baseline=""
if [ -f "$BASELINE_FILE" ]; then
  baseline=$(awk -F'ratio=' '/^ratio=/ {print $2; exit}' "$BASELINE_FILE" | tr -d ' ')
fi

if [ -z "$baseline" ]; then
  echo "no baseline recorded. write one with:"
  echo "  printf 'corpus=%s\\nratio=%s\\nrecorded=%s\\n' \"$CORPUS\" \"$ratio\" \"$(date -u +%Y-%m-%d)\" > $BASELINE_FILE"
  exit 0
fi

echo "baseline $baseline"
awk -v r="$ratio" -v b="$baseline" -v t="$TOLERANCE" '
BEGIN {
  if (b > 0 && r > b * t) { printf "REGRESSION ratio %s is more than %.1fx the baseline %s\n", r, t, b; exit 1 }
  if (b > 0 && r < b / t) { printf "note ratio %s is much lower than baseline %s. that is a fix or blindness, and it needs a human\n", r, b; exit 0 }
  printf "within tolerance\n"
  exit 0
}'
