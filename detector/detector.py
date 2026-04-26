"""
Anomaly detection using two independent sliding windows — per-IP and global.
No rate-limiting libraries used. Pure deque-based timestamp eviction.

Detection logic:
  1. Per-IP: flag if z-score > threshold OR rate > N × baseline mean
  2. Error surge tightening: if error rate is surging, lower both thresholds
  3. Global: flag if global rate exceeds threshold (DDoS from many IPs)
"""
import asyncio
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class WindowState:
    timestamps: deque = field(default_factory=deque)
    error_timestamps: deque = field(default_factory=deque)


class AnomalyDetector:
    def __init__(
        self,
        per_ip_window: int = 60,
        global_window: int = 60,
        zscore_threshold: float = 3.0,
        rate_multiplier: float = 5.0,
        error_rate_multiplier: float = 3.0,
        error_surge_tightening: float = 0.6,
    ):
        self._per_ip_window = per_ip_window
        self._global_window = global_window
        self._zscore_threshold = zscore_threshold
        self._rate_multiplier = rate_multiplier
        self._error_rate_multiplier = error_rate_multiplier
        self._tightening = error_surge_tightening

        self._ip_windows: Dict[str, WindowState] = {}
        self._global_window_state: WindowState = WindowState()
        self._lock = asyncio.Lock()

    def _evict(self, window: WindowState, cutoff: float) -> None:
        """Remove timestamps older than cutoff from both deques."""
        while window.timestamps and window.timestamps[0] < cutoff:
            window.timestamps.popleft()
        while window.error_timestamps and window.error_timestamps[0] < cutoff:
            window.error_timestamps.popleft()

    def _rates(self, window: WindowState, cutoff: float, window_seconds: int):
        """Return (req_rate, error_rate) per second after evicting stale entries."""
        self._evict(window, cutoff)
        req_rate = len(window.timestamps) / window_seconds
        error_rate = len(window.error_timestamps) / window_seconds
        return req_rate, error_rate

    async def record(self, ip: str, ts: float, status: int) -> None:
        """Record a single request. Must be called for every log entry."""
        is_error = status >= 400
        async with self._lock:
            if ip not in self._ip_windows:
                self._ip_windows[ip] = WindowState()
            self._ip_windows[ip].timestamps.append(ts)
            if is_error:
                self._ip_windows[ip].error_timestamps.append(ts)

            self._global_window_state.timestamps.append(ts)
            if is_error:
                self._global_window_state.error_timestamps.append(ts)

    async def check(
        self,
        ip: str,
        mean: float,
        stddev: float,
        baseline_error_rate: float,
    ) -> Optional[Dict]:
        """
        Check for anomalies after recording the request.
        Returns an anomaly dict if triggered, else None.
        Checks per-IP first; falls through to global.
        """
        now = time.time()
        ip_cutoff = now - self._per_ip_window
        global_cutoff = now - self._global_window

        async with self._lock:
            # --- Per-IP check ---
            ip_window = self._ip_windows.get(ip)
            if ip_window:
                ip_rate, ip_error_rate = self._rates(ip_window, ip_cutoff, self._per_ip_window)

                # Error surge tightening: lower thresholds when errors are surging
                zscore_thresh = self._zscore_threshold
                rate_thresh = self._rate_multiplier
                if baseline_error_rate > 0 and ip_error_rate > self._error_rate_multiplier * baseline_error_rate:
                    zscore_thresh *= self._tightening
                    rate_thresh *= self._tightening

                # Z-score calculation (guard against zero stddev)
                zscore = (ip_rate - mean) / stddev if stddev > 0 else 0.0

                triggered_zscore = zscore > zscore_thresh
                triggered_rate = mean > 0 and ip_rate > rate_thresh * mean

                if triggered_zscore or triggered_rate:
                    condition = (
                        f"zscore={zscore:.2f} > {zscore_thresh:.1f}"
                        if triggered_zscore
                        else f"rate={ip_rate:.2f} > {rate_thresh:.1f}x mean ({mean:.2f})"
                    )
                    return {
                        "type": "per_ip",
                        "ip": ip,
                        "rate": round(ip_rate, 3),
                        "mean": round(mean, 3),
                        "stddev": round(stddev, 3),
                        "zscore": round(zscore, 3),
                        "condition": condition,
                    }

            # --- Global check ---
            global_rate, _ = self._rates(
                self._global_window_state, global_cutoff, self._global_window
            )
            global_zscore = (global_rate - mean) / stddev if stddev > 0 else 0.0

            if global_zscore > self._zscore_threshold or (mean > 0 and global_rate > self._rate_multiplier * mean):
                condition = (
                    f"global zscore={global_zscore:.2f} > {self._zscore_threshold}"
                    if global_zscore > self._zscore_threshold
                    else f"global rate={global_rate:.2f} > {self._rate_multiplier}x mean"
                )
                return {
                    "type": "global",
                    "ip": None,
                    "rate": round(global_rate, 3),
                    "mean": round(mean, 3),
                    "stddev": round(stddev, 3),
                    "zscore": round(global_zscore, 3),
                    "condition": condition,
                }

        return None

    async def top_ips(self, n: int = 10) -> List[Dict]:
        """Return top N IPs by current per-IP request rate."""
        now = time.time()
        result = []
        async with self._lock:
            for ip, window in self._ip_windows.items():
                cutoff = now - self._per_ip_window
                self._evict(window, cutoff)
                rate = len(window.timestamps) / self._per_ip_window
                if rate > 0:
                    result.append({"ip": ip, "rate": round(rate, 3)})
        result.sort(key=lambda x: x["rate"], reverse=True)
        return result[:n]

    async def global_rate(self) -> float:
        """Return current global request rate per second."""
        now = time.time()
        cutoff = now - self._global_window
        async with self._lock:
            self._evict(self._global_window_state, cutoff)
            rate = len(self._global_window_state.timestamps) / self._global_window
        return round(rate, 3)