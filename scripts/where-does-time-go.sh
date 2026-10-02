#!/usr/bin/env bash
# Where does a `heides check` spend its time, in seconds?
#
# This exists because the answer was guessed at five times and was wrong every
# time. Two of those guesses were misread numbers rather than wrong theories, so
# the first job here is to produce a number that cannot be misread: one run, one
# total, one line per layer, in seconds, with percentages that add up.
#
# It runs the same corpus at several sizes. A single measurement says how slow it
# is; the scaling says whether the cost is linear per file or blows up, and that
# is the difference between "add a prefilter" and "find the loop".
#
# Usage:
#   scripts/where-does-time-go.sh <dir> [max_files]
#
# Example:
#   scripts/where-does-time-go.sh ~/llama.cpp/tools/ui/src
set -uo pipefail

TARGET="${1:?usage: where-does-time-go.sh <dir> [max_files]}"
MAX_FILES="${2:-0}"

# Resolve the binary: an explicit HEIDES_BIN wins, then the release build, then
# whatever is on PATH. Profiling against a different binary than the one under
# test is how a session produced numbers that could not be reproduced.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -z "${HEIDES_BIN:-}" ]]; then
  if [[ -x "$ROOT/target/release/heides" ]]; then
    HEIDES_BIN="$ROOT/target/release/heides"
  elif [[ -x "$ROOT/target/profiling/heides" ]]; then
    HEIDES_BIN="$ROOT/target/profiling/heides"
  else
    HEIDES_BIN="$(command -v heides || true)"
  fi
fi
if [[ -z "$HEIDES_BIN" || ! -x "$HEIDES_BIN" ]]; then
  echo "no heides binary found; set HEIDES_BIN" >&2
  exit 1
fi

if [[ ! -d "$TARGET" ]]; then
  echo "not a directory: $TARGET" >&2
  exit 1
fi

# The update checker spawns a detached child that does a network call. It is
# rate limited to once a day, but a first run spawns it, and a spawned child
# holding the terminal makes a timing run look like a hang. It is not part of
# what is being measured here.
export HEIDES_NO_UPDATE_CHECK=1

echo "binary:  $HEIDES_BIN"
echo "version: $("$HEIDES_BIN" --version 2>/dev/null | head -1)"
echo "corpus:  $(cd "$TARGET" && pwd)"
echo

# A scratch workspace per size, so file counts are exact rather than filtered by
# whatever the indexer happens to skip. Copying is honest; hardlinking would be
# faster but is not worth the subtlety.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Collect the files the tool would actually analyse, in a stable order.
#
# A plain file list rather than `mapfile`: `mapfile` needs /dev/fd, which is not
# available under proot, and this script is run inside the container. A tool that
# cannot measure the container is no use for diagnosing a slow check in it.
LIST="$WORK/files.txt"
(cd "$TARGET" && find . -type f \
  \( -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.jsx' \
     -o -name '*.mjs' -o -name '*.cjs' -o -name '*.py' -o -name '*.rs' \
     -o -name '*.go' -o -name '*.java' -o -name '*.php' -o -name '*.rb' \
     -o -name '*.cs' -o -name '*.html' -o -name '*.css' \) \
  | sed 's|^\./||' | sort) > "$LIST"

TOTAL_FILES=$(wc -l < "$LIST" | tr -d ' ')
if [[ "$MAX_FILES" -gt 0 && "$MAX_FILES" -lt "$TOTAL_FILES" ]]; then
  LIMIT=$MAX_FILES
else
  LIMIT=$TOTAL_FILES
fi

if [[ "$LIMIT" -eq 0 ]]; then
  echo "no analysable source files under $TARGET" >&2
  exit 1
fi

printf '%-9s %-8s %-9s %-9s %-9s\n' "files" "bytes" "wall_s" "per_file" "verdict"
printf '%s\n' "-------------------------------------------------------------"

# Sizes are doubled, not arbitrary, because the question is whether cost per file
# stays flat. 1, 2, 4, 8... shows the trend fastest with the fewest runs.
SIZES=()
n=1
while [[ $n -le $LIMIT ]]; do
  SIZES+=("$n")
  if [[ ${#SIZES[@]} -ge 7 ]]; then
    break
  fi
  n=$((n * 2))
done
# Always include the full corpus when it is not already the last size, because
# the whole-corpus number is the one that matters and doubling may skip it.
if [[ "$LIMIT" -ne "${SIZES[-1]}" ]]; then
  SIZES+=("$LIMIT")
fi

PREV_PER=""
for n in "${SIZES[@]}"; do
  rm -rf "$WORK/w"
  mkdir -p "$WORK/w"
  head -n "$n" "$LIST" | while IFS= read -r f; do
    mkdir -p "$WORK/w/$(dirname "$f")"
    cp "$TARGET/$f" "$WORK/w/$f"
  done

  BYTES=$(find "$WORK/w" -type f -printf '%s\n' 2>/dev/null | awk '{s+=$1} END {print s+0}')
  # `time` on a builtin in a pipeline is unreliable, so read the clock directly.
  START=$(date +%s.%N)
  "$HEIDES_BIN" check --no-deps "$WORK/w" >/dev/null 2>"$WORK/err.txt"
  RC=$?
  END=$(date +%s.%N)

  # A crashed run is not a fast run. On this platform a release binary can abort
  # on a TLS alignment complaint before doing any work, and reporting that as
  # 0.07s would make the whole table a lie. A check that exits non zero because
  # it found findings is fine; a signal, or an abort, is not a measurement.
  if grep -aqE "TLS segment is underaligned|panicked at" "$WORK/err.txt"; then
    echo
    echo "ABORTED at $n files, not a timing result:"
    head -2 "$WORK/err.txt" | sed 's/^/  /'
    echo
    echo "This is the android loader, not heides. Rebuild and retry:"
    echo "  cargo build --release"
    exit 1
  fi

  WALL=$(awk -v a="$START" -v b="$END" 'BEGIN { printf "%.2f", b - a }')
  PER=$(awk -v w="$WALL" -v n="$n" 'BEGIN { printf "%.4f", (n > 0 ? w / n : 0) }')

  VERDICT="ok"
  if [[ "$RC" -ge 128 ]]; then
    VERDICT="SIGNAL $((RC - 128))"
  elif [[ "$RC" -eq 124 ]]; then
    VERDICT="TIMED OUT"
  elif [[ -n "$PREV_PER" ]]; then
    # Compare per file cost against the previous size. A flat ratio is linear. A
    # ratio that keeps climbing is superlinear, and that is the case worth
    # stopping for.
    RATIO=$(awk -v a="$PER" -v b="$PREV_PER" 'BEGIN { printf "%.2f", (b > 0 ? a / b : 0) }')
    VERDICT="x${RATIO} per file"
    if awk -v r="$RATIO" 'BEGIN { exit !(r > 1.6) }'; then
      VERDICT="$VERDICT  SUPERLINEAR"
    fi
  fi

  printf '%-9s %-8s %-9s %-9s %-9s\n' "$n" "$((BYTES / 1024))K" "$WALL" "$PER" "$VERDICT"

  # The layer breakdown is only printed for the full corpus, where a single
  # aggregate is worth reading. Printing it seven times buries it.
  if [[ "$n" == "$LIMIT" ]]; then
    echo
    echo "layer breakdown, full corpus:"
    grep -aE "^heides timing|^  [a-z_]+ +[0-9]" "$WORK/err.txt" | head -12 \
      || echo "  (no HEIDES_TIMING output; run with HEIDES_TIMING=1)"
    echo
    echo "slowest files:"
    sed -n '/slowest files:/,$p' "$WORK/err.txt" | head -11 \
      || echo "  (none over the threshold)"
  fi

  PREV_PER="$PER"
done

cat <<'NOTE'

Reading the verdict column:

  ok                 first run, nothing to compare against
  x1.0 per file      cost per file is flat, so the check is linear and the
                     total grows only with repository size
  SUPERLINEAR        cost per file climbed by more than 1.6x. This is the case
                     that matters: it means per file work depends on other
                     files, so a repository twice the size is worse than twice
                     as slow, and no per file filter will fix it.

A linear verdict with an unacceptable total is a different problem from a
superlinear verdict with an acceptable total, and they need different fixes.
NOTE
