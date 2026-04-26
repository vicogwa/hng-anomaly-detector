"""
Live metrics dashboard served via aiohttp at port 8080.
Auto-refreshes every 3 seconds via JS polling /metrics endpoint.

Endpoints:
  GET /         — HTML dashboard page
  GET /metrics  — JSON metrics payload
"""
import time
from datetime import datetime, timezone

import psutil
from aiohttp import web

_start_time = time.time()


def build_dashboard_app(baseline_tracker, blocker, detector) -> web.Application:
    app = web.Application()

    async def metrics(request: web.Request) -> web.Response:
        mean, stddev, samples = baseline_tracker.snapshot()
        bans = await blocker.all_bans()
        top_ips = await detector.top_ips(10)
        g_rate = await detector.global_rate()
        hourly = baseline_tracker.hourly_history()
        sparkline = baseline_tracker.baseline_history_60s()

        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        uptime_s = int(time.time() - _start_time)

        data = {
            "uptime_seconds": uptime_s,
            "global_rate": g_rate,
            "effective_mean": round(mean, 4),
            "effective_stddev": round(stddev, 4),
            "sample_count": samples,
            "cpu_percent": cpu,
            "memory_percent": round(mem.percent, 1),
            "memory_used_mb": round(mem.used / 1024 / 1024, 1),
            "banned_ips": bans,
            "top_ips": top_ips,
            "hourly_baselines": hourly,
            "sparkline": sparkline,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return web.json_response(data)

    async def index(request: web.Request) -> web.Response:
        return web.Response(text=_HTML, content_type="text/html")

    app.router.add_get("/", index)
    app.router.add_get("/metrics", metrics)
    return app


async def run_dashboard(app: web.Application, host: str, port: int) -> None:
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    print(f"[dashboard] Listening on {host}:{port}", flush=True)


_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HNG Anomaly Detector</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
  h1 { color: #58a6ff; font-size: 1.4em; margin-bottom: 20px; }
  h2 { color: #8b949e; font-size: 0.8em; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 10px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 22px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px; }
  .card .val { font-size: 1.9em; font-weight: bold; color: #58a6ff; }
  .card .label { font-size: 0.73em; color: #8b949e; margin-top: 4px; }
  .section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px; margin-bottom: 14px; }
  table { width: 100%; border-collapse: collapse; font-size: 0.83em; }
  td, th { padding: 6px 10px; text-align: left; border-bottom: 1px solid #21262d; }
  th { color: #8b949e; font-weight: normal; }
  .banned { color: #f85149; }
  .bar-wrap { display: flex; align-items: flex-end; gap: 4px; height: 90px; margin-top: 10px; }
  .bar { background: #1f6feb; flex: 1; min-width: 8px; border-radius: 2px 2px 0 0; position: relative; }
  .bar span { position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%);
               font-size: 8px; color: #8b949e; white-space: nowrap; padding-bottom: 2px; }
  .spark { display: flex; align-items: flex-end; gap: 1px; height: 44px; margin-top: 8px; }
  .spark-bar { background: #388bfd; flex: 1; border-radius: 1px 1px 0 0; }
  #status { font-size: 0.72em; color: #8b949e; margin-top: 14px; }
  .uptime { color: #3fb950; }
</style>
</head>
<body>
<h1>&#x1F6E1; HNG Anomaly Detector &mdash; Live Dashboard</h1>

<div class="grid">
  <div class="card"><div class="val" id="global-rate">&#x2014;</div><div class="label">Global req/s</div></div>
  <div class="card"><div class="val" id="mean">&#x2014;</div><div class="label">Effective Mean (req/s)</div></div>
  <div class="card"><div class="val" id="stddev">&#x2014;</div><div class="label">Std Deviation</div></div>
  <div class="card"><div class="val" id="banned-count">&#x2014;</div><div class="label">Banned IPs</div></div>
  <div class="card"><div class="val" id="cpu">&#x2014;</div><div class="label">CPU %</div></div>
  <div class="card"><div class="val" id="mem">&#x2014;</div><div class="label">Memory %</div></div>
  <div class="card"><div class="val uptime" id="uptime">&#x2014;</div><div class="label">Uptime</div></div>
</div>

<div class="section">
  <h2>Baseline — Hourly Effective Mean (req/s)</h2>
  <div class="bar-wrap" id="hourly-bars"><span style="color:#8b949e">Collecting baseline data&hellip;</span></div>
</div>

<div class="section">
  <h2>Traffic Sparkline (last ~2 min)</h2>
  <div class="spark" id="sparkline"></div>
</div>

<div class="section">
  <h2>Banned IPs</h2>
  <table>
    <thead><tr><th>IP</th><th>Condition</th><th>Bans</th><th>Rate</th><th>Unban At</th></tr></thead>
    <tbody id="banned-table"></tbody>
  </table>
</div>

<div class="section">
  <h2>Top 10 Source IPs (current window)</h2>
  <table>
    <thead><tr><th>IP</th><th>Rate (req/s)</th></tr></thead>
    <tbody id="top-ips-table"></tbody>
  </table>
</div>

<div id="status">Last updated: <span id="last-update">&#x2014;</span></div>

<script>
function fmtUptime(s) {
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  return h + 'h ' + m + 'm ' + sec + 's';
}

async function refresh() {
  try {
    const r = await fetch('/metrics');
    const d = await r.json();

    document.getElementById('global-rate').textContent = d.global_rate;
    document.getElementById('mean').textContent = d.effective_mean;
    document.getElementById('stddev').textContent = d.effective_stddev;
    document.getElementById('banned-count').textContent = d.banned_ips.length;
    document.getElementById('cpu').textContent = d.cpu_percent + '%';
    document.getElementById('mem').textContent = d.memory_percent + '%';
    document.getElementById('uptime').textContent = fmtUptime(d.uptime_seconds);

    // Hourly baseline bar chart
    const bars = document.getElementById('hourly-bars');
    if (d.hourly_baselines && d.hourly_baselines.length > 0) {
      const maxMean = Math.max(...d.hourly_baselines.map(h => h.mean), 1);
      bars.innerHTML = d.hourly_baselines.map(h => {
        const pct = Math.max(4, Math.round((h.mean / maxMean) * 100));
        return '<div class="bar" style="height:' + pct + '%">'
             + '<span>' + h.hour + ':00<br>' + h.mean.toFixed(2) + '</span></div>';
      }).join('');
    } else {
      bars.innerHTML = '<span style="color:#8b949e">Collecting baseline data\u2026</span>';
    }

    // Sparkline
    const spark = document.getElementById('sparkline');
    if (d.sparkline && d.sparkline.length > 0) {
      const maxV = Math.max(...d.sparkline, 1);
      spark.innerHTML = d.sparkline.map(v => {
        const pct = Math.max(2, Math.round((v / maxV) * 100));
        return '<div class="spark-bar" style="height:' + pct + '%"></div>';
      }).join('');
    }

    // Banned IPs table
    const bt = document.getElementById('banned-table');
    if (d.banned_ips.length === 0) {
      bt.innerHTML = '<tr><td colspan="5" style="color:#8b949e">No active bans</td></tr>';
    } else {
      bt.innerHTML = d.banned_ips.map(b => {
        const unban = b.unban_at ? new Date(b.unban_at * 1000).toUTCString() : 'PERMANENT';
        return '<tr>'
          + '<td class="banned">' + b.ip + '</td>'
          + '<td>' + b.condition + '</td>'
          + '<td>' + b.ban_count + '</td>'
          + '<td>' + b.rate + '</td>'
          + '<td>' + unban + '</td>'
          + '</tr>';
      }).join('');
    }

    // Top IPs table
    const tt = document.getElementById('top-ips-table');
    tt.innerHTML = d.top_ips.length > 0
      ? d.top_ips.map(t => '<tr><td>' + t.ip + '</td><td>' + t.rate + '</td></tr>').join('')
      : '<tr><td colspan="2" style="color:#8b949e">No traffic yet</td></tr>';

    document.getElementById('last-update').textContent = new Date().toUTCString();
  } catch(e) {
    document.getElementById('last-update').textContent = 'Error: ' + e.message;
  }
}

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>"""