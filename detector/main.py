"""
Entry point for the HNG Anomaly Detection Engine.

Single asyncio event loop coordinating:
  - Log tail (monitor.py)
  - Baseline tracking (baseline.py)
  - Anomaly detection (detector.py)
  - IP blocking via iptables (blocker.py)
  - Auto-unban scheduling (unbanner.py)
  - Slack notifications (notifier.py)
  - Live dashboard (dashboard.py)
  - Structured audit log (audit.py)
"""
import asyncio
import os
import time

import yaml

import audit
from baseline import BaselineTracker
from blocker import IPBlocker
from dashboard import build_dashboard_app, run_dashboard
from detector import AnomalyDetector
from monitor import tail_log
from notifier import SlackNotifier
from unbanner import UnbanScheduler

# Per-IP alert cooldown to prevent alert spam (seconds)
_alert_cooldown: dict = {}
ALERT_COOLDOWN_SECONDS = 15


async def main() -> None:
    # ── Load config ──────────────────────────────────────────────────────────
    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    with open(config_path) as f:
        cfg = yaml.safe_load(f)

    det_cfg = cfg["detection"]
    log_cfg = cfg["log"]
    dash_cfg = cfg["dashboard"]
    blk_cfg = cfg["blocking"]

    # ── Configure audit log ──────────────────────────────────────────────────
    audit.configure(log_cfg["audit_log"])

    # ── Slack webhook: env var takes priority over config file ───────────────
    webhook_url = (
        os.environ.get("SLACK_WEBHOOK_URL", "").strip()
        or cfg.get("slack", {}).get("webhook_url", "").strip()
    )

    # ── Instantiate all components ────────────────────────────────────────────
    baseline = BaselineTracker(
        window_minutes=det_cfg["baseline_window_minutes"],
        recalc_interval=det_cfg["baseline_recalc_interval"],
        min_samples=det_cfg["baseline_min_samples"],
        floor_mean=det_cfg["baseline_floor_mean"],
        floor_stddev=det_cfg["baseline_floor_stddev"],
    )

    detector = AnomalyDetector(
        per_ip_window=det_cfg["per_ip_window_seconds"],
        global_window=det_cfg["global_window_seconds"],
        zscore_threshold=det_cfg["zscore_threshold"],
        rate_multiplier=det_cfg["rate_multiplier_threshold"],
        error_rate_multiplier=det_cfg["error_rate_surge_multiplier"],
    )

    blocker = IPBlocker(
        backoff_schedule=blk_cfg["unban_schedule_minutes"],
        permanent_after=blk_cfg["permanent_after_cycles"],
    )

    notifier = SlackNotifier(webhook_url)

    unbanner = UnbanScheduler(blocker, notifier)

    # ── Start dashboard ───────────────────────────────────────────────────────
    dash_app = build_dashboard_app(baseline, blocker, detector)
    await run_dashboard(dash_app, dash_cfg["host"], dash_cfg["port"])

    # ── Background tasks ──────────────────────────────────────────────────────
    asyncio.create_task(unbanner.run())

    async def recalc_loop() -> None:
        while True:
            result = await baseline.maybe_recalculate()
            if result:
                mean, stddev, samples = result
                await audit.log_baseline_recalc(mean, stddev, samples)
            await asyncio.sleep(10)

    asyncio.create_task(recalc_loop())

    # ── Main log-tailing loop ─────────────────────────────────────────────────
    log_path = log_cfg["nginx_access_log"]
    print(f"[+] HNG Anomaly Detector started. Tailing {log_path}", flush=True)

    async for entry in tail_log(log_path):
        try:
            # Extract IP: prefer source_ip (X-Forwarded-For) over remote_addr
            ip = (
                entry.get("source_ip")
                or entry.get("remote_addr")
                or "unknown"
            )
            # Strip trailing comma or multiple IPs from X-Forwarded-For
            if "," in ip:
                ip = ip.split(",")[0].strip()

            status = int(entry.get("status", 200))
            ts = time.time()

            # Feed both components
            await baseline.record(ts)
            await detector.record(ip, ts, status)

            # Get current baseline stats
            mean, stddev, _ = baseline.snapshot()
            baseline_error_rate = 0.0  # extended: track per-IP error rate separately

            # Run anomaly check
            anomaly = await detector.check(ip, mean, stddev, baseline_error_rate)
            if anomaly is None:
                continue

            # Cooldown: suppress repeated alerts for the same source within 15s
            cooldown_key = anomaly["ip"] or "global"
            last_alert = _alert_cooldown.get(cooldown_key, 0)
            if time.time() - last_alert < ALERT_COOLDOWN_SECONDS:
                continue
            _alert_cooldown[cooldown_key] = time.time()

            # ── Handle per-IP anomaly ─────────────────────────────────────────
            if anomaly["type"] == "per_ip":
                duration = await blocker.ban(
                    ip=anomaly["ip"],
                    condition=anomaly["condition"],
                    rate=anomaly["rate"],
                    baseline=mean,
                )

                await notifier.send_ban(
                    ip=anomaly["ip"],
                    condition=anomaly["condition"],
                    rate=anomaly["rate"],
                    baseline=mean,
                    duration_minutes=duration,
                )

                await audit.log_ban(
                    ip=anomaly["ip"],
                    condition=anomaly["condition"],
                    rate=anomaly["rate"],
                    baseline=mean,
                    duration_minutes=duration if duration != -1 else 9999,
                )

                print(
                    f"[BAN] {anomaly['ip']} | {anomaly['condition']} | "
                    f"rate={anomaly['rate']:.2f} mean={mean:.2f} "
                    f"duration={'PERMANENT' if duration == -1 else str(duration) + 'm'}",
                    flush=True,
                )

            # ── Handle global anomaly ─────────────────────────────────────────
            else:
                await notifier.send_global_alert(
                    condition=anomaly["condition"],
                    rate=anomaly["rate"],
                    baseline=mean,
                )

                print(
                    f"[GLOBAL] {anomaly['condition']} | "
                    f"rate={anomaly['rate']:.2f} mean={mean:.2f}",
                    flush=True,
                )

        except Exception as exc:
            print(f"[ERROR] {exc}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())