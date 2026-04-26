"""
iptables ban management.

Applies DROP rules via iptables within 10 seconds of anomaly detection.
Stores ban records with timestamps and ban counts for backoff scheduling.
Permanent ban applied after exhausting the backoff schedule.
"""
import asyncio
import time
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class BanRecord:
    ip: str
    banned_at: float
    unban_at: float          # float("inf") means permanent
    ban_count: int
    condition: str
    rate: float
    baseline: float


class IPBlocker:
    def __init__(
        self,
        backoff_schedule: Optional[List[int]] = None,
        permanent_after: int = 3,
    ):
        # Default: 10 min, 30 min, 2 hours, then permanent
        self._backoff = backoff_schedule or [10, 30, 120]
        self._permanent_after = permanent_after
        self._bans: Dict[str, BanRecord] = {}
        self._lock = asyncio.Lock()

    def _duration_for_count(self, ban_count: int) -> int:
        """Return ban duration in minutes for the given 1-indexed ban count."""
        idx = min(ban_count - 1, len(self._backoff) - 1)
        return self._backoff[idx]

    def _is_permanent(self, ban_count: int) -> bool:
        return ban_count > self._permanent_after

    async def ban(self, ip: str, condition: str, rate: float, baseline: float) -> int:
        """
        Insert an iptables DROP rule for the given IP.
        Returns ban duration in minutes, or -1 for permanent.
        """
        async with self._lock:
            existing = self._bans.get(ip)
            ban_count = (existing.ban_count + 1) if existing else 1

        permanent = self._is_permanent(ban_count)
        duration = self._duration_for_count(ban_count)
        unban_at = float("inf") if permanent else time.time() + (duration * 60)

        # Insert at position 1 (top of INPUT chain) for immediate effect
        await self._run_iptables(["-I", "INPUT", "1", "-s", ip, "-j", "DROP"])

        async with self._lock:
            self._bans[ip] = BanRecord(
                ip=ip,
                banned_at=time.time(),
                unban_at=unban_at,
                ban_count=ban_count,
                condition=condition,
                rate=rate,
                baseline=baseline,
            )

        return -1 if permanent else duration

    async def unban(self, ip: str) -> bool:
        """Remove iptables DROP rule. Returns True if a ban record existed."""
        await self._run_iptables(["-D", "INPUT", "-s", ip, "-j", "DROP"])
        async with self._lock:
            if ip in self._bans:
                del self._bans[ip]
                return True
        return False

    async def expired_bans(self) -> List[BanRecord]:
        """Return all non-permanent ban records whose unban time has passed."""
        now = time.time()
        async with self._lock:
            return [
                r for r in self._bans.values()
                if r.unban_at != float("inf") and r.unban_at <= now
            ]

    async def all_bans(self) -> List[Dict]:
        """Return serialisable list of all current ban records for the dashboard."""
        async with self._lock:
            return [
                {
                    "ip": r.ip,
                    "banned_at": r.banned_at,
                    "unban_at": r.unban_at if r.unban_at != float("inf") else None,
                    "ban_count": r.ban_count,
                    "condition": r.condition,
                    "rate": round(r.rate, 3),
                    "baseline": round(r.baseline, 3),
                }
                for r in self._bans.values()
            ]

    @staticmethod
    async def _run_iptables(args: List[str]) -> None:
        """Execute an iptables command asynchronously."""
        proc = await asyncio.create_subprocess_exec(
            "iptables", *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0 and stderr:
            # Log but don't raise — a duplicate rule removal is not fatal
            print(f"[iptables] {' '.join(args)} => {stderr.decode().strip()}", flush=True)