"""
Auto-unban scheduler.

Polls every 30 seconds for expired bans and removes them.
Owns notification and audit logging on unban.
Fully decoupled from blocker.py — blocker handles mechanics, this handles scheduling.
"""
import asyncio

import audit
from blocker import IPBlocker
from notifier import SlackNotifier


class UnbanScheduler:
    def __init__(
        self,
        blocker: IPBlocker,
        notifier: SlackNotifier,
        poll_interval: int = 30,
    ):
        self._blocker = blocker
        self._notifier = notifier
        self._poll_interval = poll_interval

    async def run(self) -> None:
        """Main loop. Runs indefinitely as a background asyncio task."""
        print(f"[unbanner] Started. Polling every {self._poll_interval}s.", flush=True)
        while True:
            await asyncio.sleep(self._poll_interval)
            await self._process_expired()

    async def _process_expired(self) -> None:
        """Check for expired bans and process each one."""
        expired = await self._blocker.expired_bans()
        for record in expired:
            await self._blocker.unban(record.ip)

            await self._notifier.send_unban(
                ip=record.ip,
                condition=record.condition,
                rate=record.rate,
                baseline=record.baseline,
            )

            await audit.log_unban(
                ip=record.ip,
                condition=record.condition,
                rate=record.rate,
                baseline=record.baseline,
            )

            print(
                f"[UNBAN] {record.ip} | condition={record.condition} | "
                f"ban_count={record.ban_count}",
                flush=True,
            )