#!/usr/bin/env python3
"""TimesFM zero shot forecast smoke test.

Feeds a repo health shaped series into the hosted open weights model and
prints a forecast with quantiles. Runs on CPU, no GPU needed.
"""
import json
import time

import timesfm

HORIZON = 8
# Demo series: weekly build seconds of a growing codebase, 40 points.
# Clearly synthetic, shaped like a real workload history.
SERIES = [10 + i * 0.35 + (i % 5) + (i * i) / 220.0 for i in range(40)]


def main() -> None:
    t0 = time.time()
    hparams = timesfm.TimesFmHparams(backend="cpu", per_core_batch_size=32, horizon=HORIZON)
    checkpoint = timesfm.TimesFmCheckpoint(hf_model="google/timesfm-2.0-500m-pytorch")
    tfm = timesfm.TimesFm(hparams=hparams, checkpoint=checkpoint)
    print(f"model loaded in {time.time() - t0:.1f}s", flush=True)

    t1 = time.time()
    out = tfm.forecast([SERIES], horizon=HORIZON)[0]
    print(f"forecast computed in {time.time() - t1:.1f}s", flush=True)

    print("input tail:", [round(x, 2) for x in SERIES[-6:]])
    print("mean forecast:", [round(x, 2) for x in out["mean"]])
    for q in out.get("quantiles", []):
        print(f"quantile {q['quantile']}:", [round(x, 2) for x in q["values"]])


if __name__ == "__main__":
    main()
