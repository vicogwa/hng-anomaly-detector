"""
Async log tailer. Handles log rotation (inode change) and truncation.
Yields parsed JSON dicts. Skips malformed lines silently.
"""
import asyncio
import json
import os
from typing import AsyncGenerator, Dict, Any


async def tail_log(path: str, poll_interval: float = 0.1) -> AsyncGenerator[Dict[str, Any], None]:
    """
    Tail a log file asynchronously, yielding one parsed JSON dict per line.
    Handles log rotation by detecting inode changes.
    Handles truncation by detecting when file position exceeds file size.
    """
    # Wait for file to exist on startup (e.g., nginx hasn't started yet)
    while not os.path.exists(path):
        print(f"[monitor] Waiting for log file: {path}", flush=True)
        await asyncio.sleep(1.0)

    f = open(path, "r")
    current_inode = os.fstat(f.fileno()).st_ino
    f.seek(0, 2)  # seek to end — don't replay old entries

    while True:
        line = f.readline()

        if not line:
            await asyncio.sleep(poll_interval)

            # Check for log rotation: inode has changed
            try:
                new_inode = os.stat(path).st_ino
            except FileNotFoundError:
                await asyncio.sleep(1.0)
                continue

            if new_inode != current_inode:
                f.close()
                f = open(path, "r")
                current_inode = new_inode
                print("[monitor] Log rotation detected, reopened file.", flush=True)
                continue

            # Check for truncation (log reset without rotation)
            pos = f.tell()
            try:
                size = os.stat(path).st_size
            except FileNotFoundError:
                await asyncio.sleep(1.0)
                continue
            if pos > size:
                f.seek(0)
                print("[monitor] Log truncation detected, seeking to start.", flush=True)

            continue

        line = line.strip()
        if not line:
            continue

        try:
            entry = json.loads(line)
            yield entry
        except (json.JSONDecodeError, ValueError):
            # Skip malformed lines silently — nginx may write partial lines
            continue