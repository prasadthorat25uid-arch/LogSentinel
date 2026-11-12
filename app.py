"""LogSentinel Flask app: python app.py"""
import csv
import io
from flask import Flask, Response, jsonify, render_template, request

from analyzer import analyze

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB upload cap


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    if "file" in request.files:
        text = request.files["file"].read().decode("utf-8", errors="ignore")
    else:
        text = (request.get_json(silent=True) or {}).get("text", "")
    if not text.strip():
        return jsonify({"error": "Empty log"}), 400
    return jsonify(analyze(text))


@app.route("/api/demo")
def api_demo():
    with open("data/sample_auth.log", encoding="utf-8") as f:
        return jsonify(analyze(f.read()))


@app.route("/api/export", methods=["POST"])
def api_export():
    rows = (request.get_json(silent=True) or {}).get("attackers", [])
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ip", "failures", "burst_5min", "severity", "users_tried", "top_user", "first_seen", "last_seen"])
    for r in rows:
        w.writerow([r["ip"], r["failures"], r["burst"], r["severity"],
                    r["users_tried"], r["top_user"], r["first_seen"], r["last_seen"]])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=logsentinel_report.csv"})


if __name__ == "__main__":
    app.run(debug=True)
