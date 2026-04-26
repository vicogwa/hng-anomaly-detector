"""
Rolling baseline engine.

Maintains a deque of per-second request counts over a configurable window (default 30 min).
Also maintains per-hour buckets so 2 AM traffic is not compared to 9 PM peak.
Recalculates mean and stddev every recalc_interval seconds.
"""
import asyncio
import math
import time
from collections import deque
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple


class BaselineTracker:
    def __init__(
        self,
        window_minutes: int = 30,
        recalc_interval: int = 60,
        min_samples: int = 10,
        floor_mean: float = 1.0,
        floor_stddev: float = 0.5,
    ):
        self._window = window_minutes * 60          # total slots (seconds)
        self._recalc_interval = recalc_interval
        self._min_samples = min_samples
        self._floor_mean = floor_mean
        self._floor_stddev = floor_stddev

        # Per-second counts for the rolling window
        self._counts: deque = deque(maxlen=self._window)

        # Per-hour slot: {hour_int: deque of per-second counts}
        self._hourly: Dict[int, deque] = {}

        # Cached stats
        self._mean: float = floor_mean
        self._stddev: float = floor_stddev
        self._sample_count: int = 0
        self._last_recalc: float = 0.0

        # Accumulator for current second
        self._current_second: int = 0
        self._current_count: int = 0

        self._lock = asyncio.Lock()

    async def record(self, timestamp: float) -> None:
        """Record a single request at the given unix timestamp."""
        sec = int(timestamp)

        async with self._lock:
            if sec != self._current_second:
                # Flush the previous second's count
                if self._current_second != 0:
                    self._counts.append(self._current_count)
                    h = datetime.fromtimestamp(self._current_second, tz=timezone.utc).hour
                    if h not in self._hourly:
                        self._hourly[h] = deque(maxlen=3600)
                    self._hourly[h].append(self._current_count)
                self._current_second = sec
                self._current_count = 1
            else:
                self._current_count += 1

    async def maybe_recalculate(self) -> Optional[Tuple[float, float, int]]:
        """
        Recalculate mean and stddev if the interval has elapsed.
        Returns (mean, stddev, sample_count) when recalculated, else None.
        """
        now = time.monotonic()
        if now - self._last_recalc < self._recalc_interval:
            return None

        async with self._lock:
            return self._recalculate()

    def _recalculate(self) -> Tuple[float, float, int]:
        """Internal recalculation. Caller must hold the lock."""
        current_hour = datetime.now(timezone.utc).hour
        hourly_data = self._hourly.get(current_hour)

        # Prefer same-hour data if there are enough samples
        if hourly_data and len(hourly_data) >= self._min_samples:
            samples = list(hourly_data)
        else:
            samples = list(self._counts)

        n = len(samples)
        if n < self._min_samples:
            # Not enough data yet — use floor values
            self._mean = self._floor_mean
            self._stddev = self._floor_stddev
            self._sample_count = n
        else:
            mean = sum(samples) / n
            variance = sum((x - mean) ** 2 for x in samples) / n
            self._mean = max(mean, self._floor_mean)
            self._stddev = max(math.sqrt(variance), self._floor_stddev)
            self._sample_count = n

        self._last_recalc = time.monotonic()
        return self._mean, self._stddev, self._sample_count

    def snapshot(self) -> Tuple[float, float, int]:
        """Return the most recently calculated (mean, stddev, sample_count)."""
        return self._mean, self._stddev, self._sample_count

    def hourly_history(self) -> List[Dict]:
        """Return [{hour, mean}, ...] for all tracked hourly slots, sorted by hour."""
        result = []
        for hour, data in sorted(self._hourly.items()):
            d = list(data)
            if d:
                result.append({"hour": hour, "mean": round(sum(d) / len(d), 4)})
        return result

    def baseline_history_60s(self) -> List[float]:
        """Return last 120 per-second counts for the dashboard sparkline."""
        counts = list(self._counts)
        return counts[-120:] if len(counts) > 120 else counts