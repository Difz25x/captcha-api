"""
run_batch.py
------------
Run pow_client.py N times in a row and report the success rate.

Usage:
  python run_batch.py              # default 100 runs
  python run_batch.py 50           # custom run count

Notes:
  - This simply invokes "python pow_client.py" in the same directory.
  - Success is detected when stdout contains the substring "success\": true"
    (as printed by pow_client after VERIFY).
  - Stdout/stderr for each run are appended to batch_logs/run_<idx>.log
    for later inspection.
"""

import subprocess
import sys
import os
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parent
LOG_DIR = ROOT / "batch_logs"
LOG_DIR.mkdir(exist_ok=True)

def run_once(idx: int) -> bool:
    log_path = LOG_DIR / f"run_{idx:03d}.log"
    with log_path.open("w", encoding="utf-8") as fh:
        proc = subprocess.run(
            [sys.executable, "pow_client.py"],
            cwd=ROOT,
            stdout=fh,
            stderr=subprocess.STDOUT,
            text=True,
        )
    # Inspect log for success flag
    out = log_path.read_text(encoding="utf-8", errors="replace")
    return 'success": true' in out or "CAPTCHA SOLVED" in out


def main():
    runs = 100
    if len(sys.argv) >= 2:
        try:
            runs = int(sys.argv[1])
        except ValueError:
            print("Invalid count; using default 100")

    successes = 0
    start = datetime.now()
    for i in range(1, runs + 1):
        print(f"[{i}/{runs}] running pow_client.py ...", end="", flush=True)
        ok = run_once(i)
        if ok:
            successes += 1
            print(" ok")
        else:
            print(" FAIL")
    duration = datetime.now() - start
    print("\n=== Batch complete ===")
    print(f"Runs:      {runs}")
    print(f"Successes: {successes}")
    print(f"Failures:  {runs - successes}")
    rate = (successes / runs * 100.0) if runs else 0.0
    print(f"Success %: {rate:.2f}%")
    print(f"Time:      {duration}")
    print(f"Logs:      {LOG_DIR}")


if __name__ == "__main__":
    main()