"""
Slack notifications via Incoming Webhooks.

All alert types include the required fields:
  condition, current rate, baseline, timestamp, and ban duration.

Failures are silently swallowed — a Slack outage must not affect detection.
"""
import asyncio
import json
from datetime import datetime, timezone
from typing import Optional

import aiohttp


class SlackNotifier:
    def __init__(self, webhook_url: str):
        self._url = webhook_url.strip()
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def _post(self, payload: dict) -> None:
        if not self._url:
            return
        try:
            session = await self._get_session()
            async with session.post(
                self._url,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                _ = await resp.text()
        except Exception as exc:
            # Never crash the daemon due to a notification failure
            print(f"[notifier] Slack post failed: {exc}", flush=True)

    async def send_ban(
        self,
        ip: str,
        condition: str,
        rate: float,
        baseline: float,
        duration_minutes: int,
    ) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        duration_str = "PERMANENT" if duration_minutes == -1 else f"{duration_minutes} min"
        payload = {
            "text": (
                f":rotating_light: *IP BANNED* `{ip}`\n"
                f"*Condition:* {condition}\n"
                f"*Current Rate:* {rate:.2f} req/s\n"
                f"*Baseline:* {baseline:.2f} req/s\n"
                f"*Ban Duration:* {duration_str}\n"
                f"*Timestamp:* {ts}"
            )
        }
        await self._post(payload)

    async def send_unban(
        self,
        ip: str,
        condition: str,
        rate: float,
        baseline: float,
    ) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        payload = {
            "text": (
                f":white_check_mark: *IP UNBANNED* `{ip}`\n"
                f"*Original Condition:* {condition}\n"
                f"*Rate at Ban:* {rate:.2f} req/s\n"
                f"*Baseline:* {baseline:.2f} req/s\n"
                f"*Timestamp:* {ts}"
            )
        }
        await self._post(payload)

    async def send_global_alert(
        self,
        condition: str,
        rate: float,
        baseline: float,
    ) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        payload = {
            "text": (
                f":warning: *GLOBAL TRAFFIC ANOMALY DETECTED*\n"
                f"*Condition:* {condition}\n"
                f"*Global Rate:* {rate:.2f} req/s\n"
                f"*Baseline:* {baseline:.2f} req/s\n"
                f"*Timestamp:* {ts}"
            )
        }
        await self._post(payload)

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()