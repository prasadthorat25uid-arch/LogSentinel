"""Generate a realistic fake SSH auth.log: python generate_sample_log.py"""
import random
from datetime import datetime, timedelta

random.seed(7)
start = datetime(datetime.now().year, 11, 5, 0, 0, 0)
lines = []

def ts(t): return t.strftime("%b %e %H:%M:%S")
def add(t, msg): lines.append((t, f"{ts(t)} server sshd[{random.randint(1000,9999)}]: {msg}"))

# normal users
for _ in range(60):
    t = start + timedelta(minutes=random.randint(0, 1400))
    add(t, f"Accepted password for {random.choice(['sanskar','admin','dev','deploy'])} from 10.0.0.{random.randint(2,30)} port {random.randint(30000,60000)} ssh2")
# occasional typos
for _ in range(10):
    t = start + timedelta(minutes=random.randint(0, 1400))
    add(t, f"Failed password for sanskar from 10.0.0.{random.randint(2,30)} port {random.randint(30000,60000)} ssh2")

# brute-forcer 1: dictionary attack on root
t0 = start + timedelta(hours=3, minutes=12)
for i in range(60):
    add(t0 + timedelta(seconds=i * 4), f"Failed password for root from 185.220.101.45 port {random.randint(30000,60000)} ssh2")
# brute-forcer 2: invalid usernames (credential stuffing)
t0 = start + timedelta(hours=9, minutes=40)
for i, u in enumerate(["admin", "test", "oracle", "ubuntu", "postgres", "git", "pi", "user", "ftp", "guest"] * 2):
    add(t0 + timedelta(seconds=i * 9), f"Failed password for invalid user {u} from 45.155.205.233 port {random.randint(30000,60000)} ssh2")
# attacker 3: succeeds after failures (compromise!)
t0 = start + timedelta(hours=15, minutes=5)
for i in range(14):
    add(t0 + timedelta(seconds=i * 11), f"Failed password for admin from 91.240.118.172 port {random.randint(30000,60000)} ssh2")
add(t0 + timedelta(seconds=170), "Accepted password for admin from 91.240.118.172 port 51234 ssh2")
# low-level noise
for ip in ["103.77.12.9", "194.26.29.14", "61.177.172.140"]:
    t0 = start + timedelta(minutes=random.randint(0, 1400))
    for i in range(random.randint(2, 4)):
        add(t0 + timedelta(minutes=i * 20), f"Failed password for invalid user pi from {ip} port {random.randint(30000,60000)} ssh2")

lines.sort(key=lambda x: x[0])
with open("data/sample_auth.log", "w") as f:
    f.write("\n".join(l for _, l in lines) + "\n")
print(f"Wrote {len(lines)} log lines to data/sample_auth.log")
