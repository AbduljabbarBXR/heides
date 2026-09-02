#!/usr/bin/env python3
"""TimesFM zero shot forecast smoke test.

Feeds a repo health shaped series into the open weights model and prints a
forecast with quantiles. Runs on CPU, no GPU needed.
"""
import time

import numpy as np
import timesfm

HORIZON = 8
# Demo series: weekly build seconds of a growing codebase, 40 points.
# Clearly synthetic, shaped like a real workload history.
SERIES = [10 + i * 0.35 + (i % 5) + (i * i) / 220.0 for i in range(40)]


def main() -> None:
    t0 = time.time()
    model = timesfm.TimesFM_2p5_200M_torch.from_pretrained(
        "google/timesfm-2.5-200m-pytorch", torch_compile=False
    )
    model.compile(
        timesfm.ForecastConfig(
            max_context=1024,
            max_horizon=256,
            normalize_inputs=True,
            use_continuous_quantile_head=True,
        )
    )
    print(f"model loaded and compiled in {time.time() - t0:.1f}s", flush=True)

    t1 = time.time()
    point, quantile = model.forecast(horizon=HORIZON, inputs=[np.array(SERIES)])
    print(f"forecast computed in {time.time() - t1:.1f}s", flush=True)

    print("input tail:", [round(float(x), 2) for x in SERIES[-6:]])
    print("point forecast:", [round(float(x), 2) for x in point[0]])
    # quantile shape (n, horizon, 10): mean, then 10th..90th
    low = quantile[0, :, 1]
    high = quantile[0, :, 9]
    print("p10 band:", [round(float(x), 2) for x in low])
    print("p90 band:", [round(float(x), 2) for x in high])


if __name__ == "__main__":
    main()
