"""Log analysis engine for LogSentinel (SSH auth.log style logs)."""
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

FAILED = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s[\d:]{8}).*Failed password for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>[\d.]+)"
)
ACCEPTED = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s[\d:]{8}).*Accepted \w+ for (?P<user>\S+) from (?P<ip>[\d.]+)"
)

THRESHOLD = 5            # failures inside the window that trigger an alert
WINDOW = timedelta(minutes=5)


def _parse_ts(ts: str, year: int) -> datetime:
    return datetime.strptime(f"{year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")


def parse(text: str, year: int = None):
    year = year or datetime.now().year
    events = []
    for line in text.splitlines():
        m = FAILED.search(line)
        if m:
            events.append(("fail", _parse_ts(m["ts"], year), m["user"], m["ip"]))
            continue
        m = ACCEPTED.search(line)
        if m:
            events.append(("ok", _parse_ts(m["ts"], year), m["user"], m["ip"]))
    return events


def _max_burst(times):
    """Largest number of failures from one IP inside the sliding window."""
    times = sorted(times)
    best, start = 0, 0
    for end, t in enumerate(times):
        while t - times[start] > WINDOW:
            start += 1
        best = max(best, end - start + 1)
    return best


def analyze(text: str, year: int = None) -> dict:
    events = parse(text, year)
    fails = defaultdict(list)
    users = defaultdict(Counter)
    successes = defaultdict(list)
    for kind, ts, user, ip in events:
        if kind == "fail":
            fails[ip].append(ts)
            users[ip][user] += 1
        else:
            successes[ip].append((ts, user))

    attackers, alerts = [], []
    for ip, times in fails.items():
        burst = _max_burst(times)
        breached = any(t > min(times) for t, _ in successes.get(ip, [])) and burst >= THRESHOLD
        if breached:
            sev = "critical"
        elif burst >= THRESHOLD * 3:
            sev = "high"
        elif burst >= THRESHOLD:
            sev = "medium"
        else:
            sev = "low"
        row = {
            "ip": ip, "failures": len(times), "burst": burst, "severity": sev,
            "users_tried": len(users[ip]),
            "top_user": users[ip].most_common(1)[0][0],
            "first_seen": min(times).strftime("%b %d %H:%M:%S"),
            "last_seen": max(times).strftime("%b %d %H:%M:%S"),
        }
        attackers.append(row)
        if sev == "critical":
            alerts.append({"severity": sev, "ip": ip,
                           "msg": f"{ip} logged in successfully AFTER {len(times)} failed attempts. Possible compromise."})
        elif sev in ("high", "medium"):
            alerts.append({"severity": sev, "ip": ip,
                           "msg": f"{ip} made {burst} failed logins within 5 minutes (brute-force pattern)."})
        if len(users[ip]) >= 5:
            alerts.append({"severity": "medium", "ip": ip,
                           "msg": f"{ip} tried {len(users[ip])} different usernames (credential stuffing)."})

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    attackers.sort(key=lambda r: (order[r["severity"]], -r["failures"]))
    alerts.sort(key=lambda a: order[a["severity"]])

    hourly = Counter()
    for kind, ts, _, _ in events:
        hourly[(kind, ts.strftime("%H:00"))] += 1
    hours = sorted({h for _, h in hourly})
    timeline = [{"hour": h, "fail": hourly[("fail", h)], "ok": hourly[("ok", h)]} for h in hours]

    all_users = Counter()
    for c in users.values():
        all_users.update(c)

    total_fail = sum(len(v) for v in fails.values())
    total_ok = sum(len(v) for v in successes.values())
    return {
        "summary": {
            "events": len(events), "failed": total_fail, "accepted": total_ok,
            "unique_ips": len(fails), "flagged_ips": sum(1 for a in attackers if a["severity"] != "low"),
        },
        "attackers": attackers[:50],
        "alerts": alerts,
        "timeline": timeline,
        "top_users": [{"user": u, "count": c} for u, c in all_users.most_common(8)],
    }
