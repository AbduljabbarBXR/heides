#!/usr/bin/env bash
# Bisect where a check stops being linear.
#
# The doubling sweep showed a cliff: flat per file cost to about 64 files, then a
# jump of 10x to 24x what a linear prediction gives at 326. This walks the sizes
# between those two points in even steps, so the size where the cost per file
# starts climbing is found rather than bracketed.
#
# Every run prints its own layer breakdown. That matters: HEIDES_TIMING reports
# only when a run finishes, so a run killed by a timeout prints nothing at all.
# Two earlier sweeps produced an empty breakdown for exactly that reason and it
# looked like the instrumentation was broken.
set -uo pipefail

TARGET="${1:?usage: bisect-nonlinear.sh <dir> <max_files> [timeout_s]}"
MAX="${2:?}"
TMO="${3:-900}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${HEIDES_BIN:-$ROOT/target/release/heides}"
[[ -x "$BIN" ]] || { echo "no binary at $BIN" >&2; exit 1; }

export HEIDES_NO_UPDATE_CHECK=1
export HEIDES_TIMING=1

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

LIST="$WORK/files.txt"
(cd "$TARGET" && find . -type f \
  \( -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.jsx' \
     -o -name '*.mjs' -o -name '*.cjs' -o -name '*.py' -o -name '*.rs' \
     -o -name '*.go' -o -name '*.java' -o -name '*.php' -o -name '*.rb' \
     -o -name '*.cs' \) | sed 's|^\./||' | sort) > "$LIST"
TOTAL=$(wc -l < "$LIST" | tr -d ' ')
echo "corpus: $TARGET"
echo "binary:  $BIN"
echo "files available: $TOTAL   timeout: ${TMO}s per size"
echo

printf '%-7s %-9s %-10s %-11s %s\n' "files" "wall_s" "per_file" "vs_linear" "layers"
printf '%s\n' "------------------------------------------------------------"

# Baseline from the smallest size, so "vs_linear" compares every size against the
# per file cost of one file rather than against the previous row. Comparing to
# the previous row hides a cliff as a single large ratio, which is how a 24x
# overshoot got printed as one unremarkable step.
BASE_PER=""

for n in $(seq 8 8 "$MAX" 2>/dev/null || echo "$MAX"); do
  [[ "$n" -le "$TOTAL" ]] || break
  rm -rf "$WORK/w"; mkdir -p "$WORK/w"
  head -n "$n" "$LIST" | while IFS= read -r f; do
    mkdir -p "$WORK/w/$(dirname "$f")"
    cp "$TARGET/$f" "$WORK/w/$f"
  done

  S=$(date +%s.%N)
  timeout "$TMO" "$BIN" check --no-deps "$WORK/w" >/dev/null 2>"$WORK/err.txt"
  RC=$?
  E=$(date +%s.%N)
  W=$(awk -v a="$S" -v b="$E" 'BEGIN { printf "%.2f", b - a }')
  PER=$(awk -v w="$W" -v n="$n" 'BEGIN { printf "%.4f", (n > 0 ? w / n : 0) }')

  if [[ "$RC" -eq 124 ]]; then
    printf '%-7s %-9s %-10s %-11s %s\n' "$n" "$W" "$PER" "-" "TIMEOUT past ${TMO}s"
    break
  fi
  if grep -aqE "TLS segment is underaligned|panicked at" "$WORK/err.txt"; then
    printf '%-7s %-9s %-10s %-11s %s\n' "$n" "$W" "$PER" "-" "ABORTED, not a timing"
    break
  fi

  if [[ -z "$BASE_PER" ]]; then
    BASE_PER="$PER"
    VS="baseline"
  else
    VS=$(awk -v a="$PER" -v b="$BASE_PER" 'BEGIN { printf "%.2fx", (b > 0 ? a / b : 0) }')
  fi

  # The dominant layer, so the cliff can be attributed without a second run.
  TOP=$(grep -aE "^  [a-z_:]+ +[0-9]+\.[0-9]+s" "$WORK/err.txt" \
        | sort -k2 -rn | head -1 | awk '{print $1" "$2}')
  printf '%-7s %-9s %-10s %-11s %s\n' "$n" "$W" "$PER" "$VS" "${TOP:-no timing}"

  # Once per file cost has doubled against the baseline the shape is established,
  # so print the whole breakdown for that size rather than continuing to guess.
  if [[ -n "$BASE_PER" ]] && awk -v a="$PER" -v b="$BASE_PER" 'BEGIN { exit !(b > 0 && a / b > 2.0) }'; then
    echo
    echo "layer breakdown at $n files, where per file cost has doubled:"
    grep -aE "^heides timing|^  [a-z_:]+ +[0-9]+\.[0-9]+s" "$WORK/err.txt" | head -10
    echo
    echo "slowest files:"
    sed -n '/slowest files:/,$p' "$WORK/err.txt" | head -8
    break
  fi
done

cat <<'NOTE'

vs_linear is per file cost against the smallest size measured, not against the
previous row. A cliff shows up as that column climbing steadily. If it stays flat
to the end, the cost is linear in file count and the total is simply too large.

The dominant layer column names the layer that owns the largest share. When it
changes as the cliff arrives, the growth is in that layer. When it does not, the
cost is spread and no single layer is responsible.
NOTE
