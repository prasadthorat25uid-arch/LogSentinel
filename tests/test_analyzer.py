from analyzer import analyze

BRUTE = "\n".join(
    f"Nov  5 03:12:{i:02d} srv sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
    for i in range(10)
)
COMPROMISE = BRUTE + "\nNov  5 03:13:30 srv sshd[1]: Accepted password for root from 1.2.3.4 port 22 ssh2"


def test_brute_force_detected():
    r = analyze(BRUTE)
    assert r["attackers"][0]["ip"] == "1.2.3.4"
    assert r["attackers"][0]["severity"] in ("medium", "high")


def test_compromise_is_critical():
    r = analyze(COMPROMISE)
    assert r["attackers"][0]["severity"] == "critical"


def test_clean_log():
    r = analyze("Nov  5 03:12:01 srv sshd[1]: Accepted password for dev from 10.0.0.2 port 22 ssh2")
    assert r["summary"]["failed"] == 0 and r["alerts"] == []
