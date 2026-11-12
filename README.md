# 🛰️ LogSentinel

A **threat radar for SSH logs**. Drop in an `auth.log` file and LogSentinel detects brute-force attacks, credential stuffing and possible compromises, then shows them in an animated glassmorphism dashboard.

## Features
- Parses `Failed password` / `Accepted password` events from SSH logs
- Sliding 5-minute window brute-force detection
- **Critical alert** when an IP logs in successfully *after* many failures (possible compromise)
- Credential-stuffing detection (one IP trying many usernames)
- Attacker leaderboard with severity levels
- Activity timeline chart (pure canvas, no libraries)
- Most-targeted usernames
- CSV report export
- Runs fully locally, logs never leave your machine

## Tech Stack
Python · Flask · HTML/CSS/vanilla JS

## Setup
```bash
git clone https://github.com/sankarkulkarni/LogSentinel.git
cd LogSentinel
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py                   # open http://127.0.0.1:5000
```
Click **Load demo attack** to see it in action, or drop in your own log (e.g. `/var/log/auth.log`).

## Generate fresh sample data
```bash
python generate_sample_log.py
```

## Run tests
```bash
pytest
```

## Project Structure
```
LogSentinel/
├── app.py                  # Flask server + API
├── analyzer.py             # detection engine
├── generate_sample_log.py  # fake attack log generator
├── data/sample_auth.log    # demo data
├── templates/index.html    # animated dashboard
└── tests/test_analyzer.py
```

## How detection works
| Pattern | Rule | Severity |
|---|---|---|
| Brute force | 5+ failures from one IP in 5 min | Medium |
| Heavy brute force | 15+ failures in 5 min | High |
| Compromise | Successful login after a brute-force burst | Critical |
| Credential stuffing | 5+ different usernames from one IP | Medium alert |

## Roadmap
- [ ] IP geolocation map
- [ ] Isolation Forest anomaly detection
- [ ] Email / Telegram alerts
- [ ] Auto-generate firewall blocklist

## What I Learned
- Parsing semi-structured logs with regex
- Sliding-window algorithms for rate-based detection
- Designing a security dashboard with canvas charts

## License
MIT © Sanskar Kulkarni
