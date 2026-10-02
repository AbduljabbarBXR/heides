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

TARGET="${1:?usage: bisect-nonlinear.sh <dir> <max_kib> [timeout_s] [step_kib]}"
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

# Sizes come from `find -printf`, which writes one record per file. Packing size
# and path into one whitespace separated line was wrong: a path may contain a
# space, and `3598 app.d.ts` then fails to parse as two numbers.
(cd "$TARGET" && find . -type f \
  \( -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.jsx' \
     -o -name '*.mjs' -o -name '*.cjs' -o -name '*.py' -o -name '*.rs' \
     -o -name '*.go' -o -name '*.java' -o -name '*.php' -o -name '*.rb' \
     -o -name '*.cs' \) -printf '%s %p\n' | sort -k2) > "$WORK/sizes.txt"
TOTAL_BYTES=$(awk '{s+=$1} END {print s+0}' "$WORK/sizes.txt")
echo "corpus: $TARGET"
echo "binary:  $BIN"
echo "files available: $TOTAL   timeout: ${TMO}s per size"
echo

printf '%-7s %-8s %-9s %-10s %-10s %s\n' "files" "KiB" "wall_s" "s/file" "s/KiB" "layers"
printf '%s\n' "------------------------------------------------------------"

# Baseline from the smallest size, so "vs_linear" compares every size against the
# per file cost of one file rather than against the previous row. Comparing to
# the previous row hides a cliff as a single large ratio, which is how a 24x
# overshoot got printed as one unremarkable step.
BASE_PER=""

# Select by byte budget, not file count.
#
# Taking the first N files in sorted order means each larger N is a different
# corpus with a different average file size, and cost per file then tracks file
# size rather than file count. Measured on this corpus, KB per file rose from 2.0
# to 4.2 across the sweep, which made a linear cost look like a 4x cliff and had
# two separate investigations chasing it. Cost per kilobyte over the same data is
# flat at about 0.08, which is the real answer.
#
# So each size here is a fixed byte budget, filled from files in a stable order.
# The reported per file cost is then comparable across sizes by construction.
BUDGET_STEP=$(( ${STEP_KB:-128} * 1024 ))
MAX_BYTES=$TOTAL_BYTES

# Iterate over a byte budget in fixed steps. MAX is the largest budget in KiB, so
# the last row is the whole corpus.
LAST_BUDGET=$(( MAX * 1024 ))
[[ "$LAST_BUDGET" -gt "$MAX_BYTES" ]] && LAST_BUDGET=$MAX_BYTES

for BUDGET in $(seq $BUDGET_STEP $BUDGET_STEP "$LAST_BUDGET"); do
  rm -rf "$WORK/w"; mkdir -p "$WORK/w"
  : > "$WORK/pick.txt"
  ACC=0
  # The size is the first field and the path is the rest of the line, so a space
  # in a filename is carried through rather than misread as a second field.
  while read -r sz f; do
    f="${f# }"
    ACC=$(( ACC + sz ))
    printf '%s\n' "$f" >> "$WORK/pick.txt"
    [[ "$ACC" -ge "$BUDGET" ]] && break
  done < "$WORK/sizes.txt"
  n=$(wc -l < "$WORK/pick.txt" | tr -d ' ')
  BYTES=$ACC
  [[ "$n" -gt 0 ]] || break
  while IFS= read -r f; do
    mkdir -p "$WORK/w/$(dirname "$f")"
    cp "$TARGET/$f" "$WORK/w/$f"
  done < "$WORK/pick.txt"

  S=$(date +%s.%N)
  timeout "$TMO" "$BIN" check --no-deps "$WORK/w" >/dev/null 2>"$WORK/err.txt"
  RC=$?
  E=$(date +%s.%N)
  W=$(awk -v a="$S" -v b="$E" 'BEGIN { printf "%.2f", b - a }')
  PER=$(awk -v w="$W" -v n="$n" 'BEGIN { printf "%.4f", (n > 0 ? w / n : 0) }')

  if [[ "$RC" -eq 124 ]]; then
    printf '%-7s %-8s %-9s %-10s %-10s %s\n' "$n" "?" "$W" "$PER" "-" "TIMEOUT past ${TMO}s"
    break
  fi
  if grep -aqE "TLS segment is underaligned|panicked at" "$WORK/err.txt"; then
    printf '%-7s %-8s %-9s %-10s %-10s %s\n' "$n" "?" "$W" "$PER" "-" "ABORTED, not a timing"
    break
  fi

  KB=$(awk -v b="$BYTES" 'BEGIN { printf "%.0f", b / 1024 }')
  PERKB=$(awk -v w="$W" -v b="$BYTES" 'BEGIN { printf "%.4f", (b > 0 ? w * 1024 / b : 0) }')
  if [[ -z "${BASE_PER:-}" ]]; then
    BASE_PER="$PERKB"
    VS="baseline"
  else
    VS=$(awk -v a="$PERKB" -v b="$BASE_PER" 'BEGIN { printf "%.2fx", (b > 0 ? a / b : 0) }')
  fi

  # The dominant layer, so the cliff can be attributed without a second run.
  TOP=$(grep -aE "^  [a-z_:]+ +[0-9]+\.[0-9]+s" "$WORK/err.txt" \
        | sort -k2 -rn | head -1 | awk '{print $1" "$2}')
  printf '%-7s %-8s %-9s %-10s %-10s %s\n' "$n" "$KB" "$W" "$PER" "$PERKB" "$VS ${TOP:-no timing}"

  # Once per file cost has doubled against the baseline the shape is established,
  # so print the whole breakdown for that size rather than continuing to guess.
  if [[ -n "${BASE_PER:-}" ]] && awk -v a="$PERKB" -v b="$BASE_PER" 'BEGIN { exit !(b > 0 && a / b > 1.6) }'; then
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

s/KiB is the column to read, not s/file. A fixed byte budget is sampled at each
size, so cost per kilobyte is comparable across rows by construction. If s/KiB
stays flat the cost is linear in code volume and the total is simply large. If it
climbs, that is superlinearity in the checker rather than in the corpus.

s/file is still printed because it is what a user feels, but it moves for two
reasons and only one of them is the tool: how much code each file contains, and
how the tool performs on it. Confusing the two is what sent two separate
investigations after a cliff that was a sorted prefix of increasingly large files.
NOTE
