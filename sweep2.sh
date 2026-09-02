#!/bin/bash
# Final full-sweep dogfood v2: full per-project logs, proper counts. Read-only.
C=/data/data/com.termux/files/usr/var/lib/proot-distro/containers/ubuntu/rootfs
H=~/heides/target/release/heides
OUT=$TMPDIR/heides_sweep2
mkdir -p "$OUT/full"
SUM=$OUT/summary.txt
: > "$SUM"
for d in "$C"/root/devops/*/; do
  name=$(basename "$d")
  t0=$(date +%s)
  timeout 500 "$H" check "$d" > "$OUT/full/$name.log" 2>&1
  rc=$?
  t1=$(date +%s)
  # counts summary is the line shaped "N blocker(s), N critical, ..."
  counts=$(grep -m1 -E "[0-9]+ blocker\(s\), [0-9]+ critical" "$OUT/full/$name.log")
  if [ -z "$counts" ]; then
    # fallback: report top severity lines found
    counts=$(grep -m1 -E "\[(blocker|critical|warning)\]" "$OUT/full/$name.log" | head -c 200)
    [ -z "$counts" ] && counts="no findings"
  fi
  echo "[$name] rc=$rc ($((t1-t0))s) $counts" >> "$SUM"
  echo "[$name] rc=$rc ($((t1-t0))s) $counts"
done
echo "SWEEP DONE" >> "$SUM"
echo "SWEEP DONE"
