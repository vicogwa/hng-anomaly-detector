"""
Structured audit log. Three event types: BAN, UNBAN, BASELINE_RECALC.
Thread-safe via asyncio lock. Writes to /var/log/detector/audit.log.
"""
import asyncio
import os
from datetime import datetime, timezone

_lock = asyncio.Lock()
_log_path: str = "/var/log/detector/audit.log"


def configure(path: str) -> None:
    global _log_path
    _log_path = path
    os.makedirs(os.path.dirname(path), exist_ok=True)


async def _write(line: str) -> None:
    async with _lock:
        with open(_log_path, "a") as f:
            f.write(line + "\n")


async def log_ban(ip: str, condition: str, rate: float, baseline: float, duration_minutes: int) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    line = (
        f"[{ts}] BAN ip={ip} | condition={condition} | "
        f"rate={rate:.2f} | baseline={baseline:.2f} | duration={duration_minutes}m"
    )
    await _write(line)


async def log_unban(ip: str, condition: str, rate: float, baseline: float) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    line = (
        f"[{ts}] UNBAN ip={ip} | condition={condition} | "
        f"rate={rate:.2f} | baseline={baseline:.2f} | duration=expired"
    )
    await _write(line)


async def log_baseline_recalc(mean: float, stddev: float, sample_count: int) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    line = (
        f"[{ts}] BASELINE_RECALC | mean={mean:.4f} | stddev={stddev:.4f} | "
        f"samples={sample_count}"
    )
    await _write(line)