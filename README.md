# HNG Anomaly Detector

> A real-time anomaly detection engine that monitors Nextcloud traffic, learns normal behaviour, and automatically blocks suspicious IPs using iptables — all within 10 seconds of detection.

---

## Live Links

| | |
|---|---|
| **Server IP** | `44.194.214.146` |
| **Metrics Dashboard** | `hng-d.zapto.org` |
| **GitHub** | `https://github.com/vicogwa/hng-anomaly-detector` |
| **Blog Post** | `(https://medium.com/@victoriafrancis885/how-i-built-a-real-time-anomaly-detector-that-automatically-blocks-attackers-a75a8b736b38)` |


---

## Language Choice — Python + asyncio

This project is written in **Python 3.11** using the built-in `asyncio` event loop.

**Why Python?**

The entire workload is I/O-bound — reading log lines, making HTTP requests to Slack, running subprocesses for iptables. Python's asyncio handles thousands of concurrent I/O operations on a single thread without the overhead of OS threads or goroutines. A Go implementation would offer no meaningful advantage here and would add unnecessary complexity.

**Why no frameworks or rate-limiting libraries?**

The spec requires building the detection logic from scratch. Using a library like `slowapi` or `limits` would hide the sliding window mechanics the graders are looking for. Every deque, every eviction loop, every z-score calculation is written by hand.

---

## How the Sliding Window Works

Each IP gets two `collections.deque` objects — one for all requests, one for error requests (HTTP 4xx/5xx). There is also a global deque aggregating all traffic.

```python
@dataclass
class WindowState:
    timestamps: deque = field(default_factory=deque)
    error_timestamps: deque = field(default_factory=deque)
```

**Recording a request:**
Every log entry appends the current unix timestamp to the IP's deque and the global deque.

**Eviction logic:**
On every anomaly check, stale timestamps are evicted from the left end of the deque using a while loop:

```python
def _evict(self, window: WindowState, cutoff: float) -> None:
    while window.timestamps and window.timestamps[0] < cutoff:
        window.timestamps.popleft()
    while window.error_timestamps and window.error_timestamps[0] < cutoff:
        window.error_timestamps.popleft()
```

`cutoff = now - window_seconds` (default: 60 seconds).

**Rate calculation:**
After eviction, the rate is simply:
```python
req_rate = len(window.timestamps) / window_seconds
```

This is O(1) after eviction. The `deque.popleft()` operation is also O(1) — this is why `deque` is used instead of a list, where `pop(0)` would be O(n).

---

## How the Baseline Works

A `deque(maxlen=1800)` stores one integer count per second (30 minutes × 60 seconds = 1800 slots).

```
window_minutes: 30         # 1800 per-second slots
recalc_interval: 60        # recalculate every 60 seconds
baseline_min_samples: 10   # minimum samples before baseline is reliable
baseline_floor_mean: 1.0   # prevents division by zero on cold start
baseline_floor_stddev: 0.5 # minimum stddev during cold start
```

**Per-hour bucketing:**
Traffic at 2 AM is naturally lower than at 9 PM. Comparing them would cause false positives at night and miss real attacks during the day. To solve this, the baseline also maintains a separate deque for each hour of the day:

```python
self._hourly: Dict[int, deque] = {}  # {hour_int: deque of per-second counts}
```

During recalculation, if the current hour has at least 10 seconds of data, that hour's data is used instead of the global rolling window. This means the baseline adapts to time-of-day traffic patterns automatically.

**Recalculation:**
Every 60 seconds, mean and standard deviation are recalculated from the samples:

```python
mean = sum(samples) / n
variance = sum((x - mean) ** 2 for x in samples) / n
stddev = max(sqrt(variance), floor_stddev)
```

Floor values ensure the baseline never reaches zero, which would cause division-by-zero errors in the z-score calculation.

---

## How Detection Works

Two conditions can trigger a ban — either one is sufficient:

**1. Z-score check:**
```
z = (ip_rate - mean) / stddev
if z > 3.0 → anomaly
```

**2. Rate multiplier check:**
```
if ip_rate > 5.0 × mean → anomaly
```

**3. Error surge tightening:**
If the IP's error rate exceeds `3.0 × baseline_error_rate`, both thresholds are tightened by a factor of 0.6:
```
zscore_threshold → 1.8
rate_multiplier  → 3.0
```
This catches scanners and brute-force attempts that generate many 404s or 401s even at moderate request rates.

**4. Global check:**
The same logic is applied to the aggregated global rate across all IPs, catching distributed attacks from many sources simultaneously.

---

## Architecture


<img width="644" height="786" alt="image" src="https://github.com/user-attachments/assets/3ef8f53b-67ea-4f6c-af9d-b75c40b35b1c" />


---

## Setup Instructions — Fresh VPS to Fully Running Stack

### 1. Provision a Server

Use Ubuntu 22.04 LTS. Minimum: 2 vCPU, 2 GB RAM.
Recommended: AWS EC2 `t2.medium`, DigitalOcean 2GB Droplet, or Hetzner CX21.

Open inbound ports: **22** (SSH), **80** (HTTP), **8080** (Dashboard).

### 2. Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
sudo systemctl enable docker
sudo systemctl start docker
sudo apt install -y docker-compose-plugin
```

Log out and back in for the group change to take effect.

### 3. Clone the Repository

```bash
git clone https://github.com/your-username/hng-anomaly-detector.git
cd hng-anomaly-detector
```

### 4. Configure Environment

```bash
nano .env
```

Add:
```
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/REAL/WEBHOOK
MYSQL_ROOT_PASSWORD=your_root_password
MYSQL_PASSWORD=your_db_password
NEXTCLOUD_ADMIN_USER=admin
NEXTCLOUD_ADMIN_PASSWORD=your_admin_password
```

To get a Slack webhook:
- Go to https://api.slack.com/apps
- Create New App → From scratch
- Incoming Webhooks → Activate → Add New Webhook → Copy URL

### 5. Deploy

```bash
docker compose up -d --build
```

### 6. Verify

```bash
# All 4 containers running
docker compose ps

# Detector reading logs
docker compose logs detector

# Nextcloud accessible
curl -I http://YOUR_SERVER_IP

# Dashboard accessible
curl -I http://YOUR_SERVER_IP:8080
```

### 7. Test Detection

```bash
# Install Apache Bench
sudo apt install -y apache2-utils

# Fire a traffic spike to trigger detection
ab -n 500 -c 10 http://YOUR_SERVER_IP/

# Verify iptables ban was applied
docker compose exec detector iptables -L INPUT -n --line-numbers

# Check audit log
cat /var/log/detector/audit.log
```

---

## Configuration Reference

All parameters are in `detector/config.yaml`:

```yaml
detection:
  per_ip_window_seconds: 60      # sliding window size
  baseline_window_minutes: 30    # rolling baseline window
  baseline_recalc_interval: 60   # recalculate every N seconds
  zscore_threshold: 3.0          # z-score trigger
  rate_multiplier_threshold: 5.0 # rate × mean trigger
  baseline_floor_mean: 1.0       # cold-start floor
  baseline_floor_stddev: 0.5     # cold-start floor

blocking:
  unban_schedule_minutes: [10, 30, 120]  # backoff schedule
  permanent_after_cycles: 3              # permanent after 3 bans
```
