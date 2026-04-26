# HNG Anomaly Detector

> Real-time anomaly detection engine for Nextcloud (cloud.ng), powered by Python asyncio and iptables.

**Server IP:** YOUR_SERVER_IP_HERE
**Metrics Dashboard:** http://monitor.yourdomain.com
**GitHub:** https://github.com/your-username/hng-anomaly-detector
**Blog Post:** https://your-blog-url-here

---

## Language Choice

**Python 3.11 + asyncio.**

The asyncio event loop gives single-threaded concurrency without the overhead of OS threads for this I/O-bound workload. The `deque` from `collections` is O(1) append/popleft — exactly what a sliding window needs. No third-party rate-limiting libraries are used.

---

## How the Sliding Window Works

Two `deque` objects per IP — one for all requests, one for error requests. Every request appends its unix timestamp. On each anomaly check, timestamps older than `window_seconds` (default: 60) are evicted from the left end with `popleft()` in a while loop. The rate is `len(deque) / window_seconds`. The global window works the same way but aggregates all IPs.

---

## How the Baseline Works

A `deque(maxlen=1800)` stores one integer count per second (30 min × 60 sec = 1800 slots). Every 60 seconds, mean and stddev are recalculated from these samples. Per-hour buckets are also maintained: if the current hour has ≥ 10 seconds of data, that hour's data is preferred so 2 AM low traffic is not compared against the 9 PM peak.

Floor values (`baseline_floor_mean: 1.0`, `baseline_floor_stddev: 0.5`) prevent division by zero during cold start.

---

## How Detection Works

1. **Z-score check:** `(ip_rate - mean) / stddev > 3.0`
2. **Multiplier check:** `ip_rate > 5.0 × mean`
3. **Error surge tightening:** if the IP's error rate exceeds `3.0 × baseline_error_rate`, both thresholds are multiplied by `0.6` (tightened to 1.8 and 3.0 respectively)
4. **Global check:** same logic applied to the aggregated global rate

Either condition on its own triggers a ban.

---

## How Blocking Works

`blocker.py` calls `iptables -I INPUT 1 -s <ip> -j DROP` via `asyncio.create_subprocess_exec`. Inserting at position 1 ensures the rule is evaluated first. **No Fail2Ban.** Backoff schedule: 10 min → 30 min → 120 min → permanent.

---

## Setup Instructions

### Prerequisites

- Ubuntu 22.04 VPS (2 vCPU, 2 GB RAM minimum)
- Docker + Docker Compose v2
- A domain/subdomain pointing to your server IP (for the dashboard)
- A Slack app with Incoming Webhooks enabled

### 1. Clone

```bash
git clone https://github.com/your-username/hng-anomaly-detector.git
cd hng-anomaly-detector
```

### 2. Configure

```bash
cp .env.example .env
nano .env   # fill in passwords and Slack webhook
nano nginx/nginx.conf   # replace monitor.yourdomain.com with your subdomain
```

### 3. Deploy

```bash
docker compose up -d --build
docker compose logs -f detector   # watch startup
```

### 4. Verify

```bash
# All 4 containers running
docker compose ps

# Nextcloud accessible
curl -I http://YOUR_SERVER_IP

# Dashboard accessible
curl -I http://monitor.yourdomain.com

# Metrics endpoint
curl http://monitor.yourdomain.com/metrics | python3 -m json.tool

# Shared log volume being written
docker compose exec nginx tail -f /var/log/nginx/hng-access.log

# Audit log
tail -f /var/log/detector/audit.log
```

### 5. Test Detection

```bash
# Trigger a ban (requires apache2-utils)
apt install apache2-utils
ab -n 500 -c 10 http://YOUR_SERVER_IP/

# Verify iptables rule was added
docker compose exec detector iptables -L INPUT -n --line-numbers
```

---

## Architecture

```
Internet → Nginx (port 80)
              │
              ├── Proxy → Nextcloud (PHP-FPM)
              │              │
              │              └── MariaDB
              │
              └── JSON logs → HNG-nginx-logs volume
                                    │
                                    └── Detector container
                                          ├── monitor.py   (tail log)
                                          ├── baseline.py  (rolling mean/stddev)
                                          ├── detector.py  (z-score + multiplier)
                                          ├── blocker.py   (iptables)
                                          ├── unbanner.py  (backoff schedule)
                                          ├── notifier.py  (Slack)
                                          ├── audit.py     (structured log)
                                          └── dashboard.py (port 8080)
```

---

## Module Summary

| Module | Responsibility |
|---|---|
| `main.py` | Entry point, event loop, orchestration |
| `monitor.py` | Async log tailer with rotation/truncation handling |
| `baseline.py` | Rolling 30-min baseline with per-hour buckets |
| `detector.py` | Z-score + multiplier anomaly detection |
| `blocker.py` | iptables DROP rule management |
| `unbanner.py` | Auto-unban scheduler with backoff |
| `notifier.py` | Slack Incoming Webhook alerts |
| `dashboard.py` | aiohttp live metrics dashboard |
| `audit.py` | Structured audit log (BAN/UNBAN/BASELINE_RECALC) |
| `config.yaml` | All tunable parameters |