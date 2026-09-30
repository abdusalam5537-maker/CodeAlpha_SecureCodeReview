"""
Secure Code Review — Flask backend.

Runs submitted source through engine.analyze() (real static analysis —
ast-based for Python, regex-based for JavaScript, see rules_python.py /
rules_javascript.py) and persists every review to data/history.json so
the Review History tab is a real audit trail, not just running totals.
"""

import json
import os
import threading
import time
import uuid

from flask import Flask, jsonify, render_template, request

import engine

app = Flask(__name__)

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
HISTORY_FILE = os.path.join(DATA_DIR, "history.json")
SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")
lock = threading.Lock()

MAX_HISTORY = 100


def load_history():
    if not os.path.exists(HISTORY_FILE):
        os.makedirs(DATA_DIR, exist_ok=True)
        save_history([])
    with open(HISTORY_FILE, "r") as f:
        return json.load(f)


def save_history(history):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)


@app.route("/")
def index():
    return render_template("index.html", languages=engine.LANGUAGES, rule_catalog=engine.all_rules())


@app.route("/api/review", methods=["POST"])
def api_review():
    body = request.get_json(silent=True) or {}
    language = body.get("language", "python")
    code = body.get("code", "")
    label = (body.get("label") or "").strip() or "Untitled submission"

    if not code.strip():
        return jsonify({"error": "No source code submitted."}), 400

    result, err = engine.analyze(language, code)
    if err:
        return jsonify({"error": err}), 400

    entry = {
        "id": uuid.uuid4().hex[:10],
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "language": language,
        "label": label,
        "score": result["score"],
        "grade": result["grade"],
        "counts": result["counts"],
        "total_lines": result["total_lines"],
        "finding_count": len(result["findings"]),
        "code": code,
        "findings": result["findings"],
    }

    with lock:
        history = load_history()
        history.insert(0, entry)
        history = history[:MAX_HISTORY]
        save_history(history)

    return jsonify(entry)


@app.route("/api/history")
def api_history():
    history = load_history()
    # Summary rows only — full code/findings are fetched per-review to keep this light.
    summary = [{k: v for k, v in h.items() if k not in ("code", "findings")} for h in history]
    return jsonify(summary)


@app.route("/api/history/<review_id>")
def api_history_detail(review_id):
    history = load_history()
    for h in history:
        if h["id"] == review_id:
            return jsonify(h)
    return jsonify({"error": "Review not found."}), 404


@app.route("/api/rules")
def api_rules():
    return jsonify(engine.all_rules())


@app.route("/api/overview")
def api_overview():
    """Aggregates across every review ever run — powers the Overview tab.
    Needs the full findings list per entry (not the stripped /api/history
    summary), so it reads history.json directly rather than reusing that route."""
    history = load_history()

    total_reviews = len(history)
    total_findings = sum(h["finding_count"] for h in history)
    avg_score = round(sum(h["score"] for h in history) / total_reviews, 1) if total_reviews else None

    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    rule_freq = {}  # rule_id -> {title, severity, count}
    language_counts = {}

    for h in history:
        language_counts[h["language"]] = language_counts.get(h["language"], 0) + 1
        for sev, count in h["counts"].items():
            severity_totals[sev] = severity_totals.get(sev, 0) + count
        for f in h["findings"]:
            entry = rule_freq.setdefault(f["rule_id"], {"title": f["title"], "severity": f["severity"], "count": 0})
            entry["count"] += 1

    top_rules = sorted(
        [{"rule_id": rid, **data} for rid, data in rule_freq.items()],
        key=lambda r: -r["count"],
    )[:8]

    best = max(history, key=lambda h: h["score"]) if history else None
    worst = min(history, key=lambda h: h["score"]) if history else None

    return jsonify({
        "total_reviews": total_reviews,
        "total_findings": total_findings,
        "avg_score": avg_score,
        "severity_totals": severity_totals,
        "language_counts": language_counts,
        "top_rules": top_rules,
        "best_review": {"label": best["label"], "score": best["score"], "timestamp": best["timestamp"]} if best else None,
        "worst_review": {"label": worst["label"], "score": worst["score"], "timestamp": worst["timestamp"]} if worst else None,
        "recent": [{"id": h["id"], "timestamp": h["timestamp"], "label": h["label"], "language": h["language"],
                    "score": h["score"], "grade": h["grade"], "finding_count": h["finding_count"]} for h in history[:5]],
    })


@app.route("/api/sample/<language>")
def api_sample(language):
    filenames = {"python": "vulnerable_sample.py", "javascript": "vulnerable_sample.js"}
    if language not in filenames:
        return jsonify({"error": "Unknown language."}), 400
    path = os.path.join(SAMPLES_DIR, filenames[language])
    with open(path) as f:
        code = f.read()
    return jsonify({"language": language, "label": filenames[language], "code": code})


@app.route("/api/reset", methods=["POST"])
def api_reset():
    with lock:
        save_history([])
    return jsonify({"ok": True})


if __name__ == "__main__":
    print("Secure Code Review running at http://localhost:5002")
    app.run(host="127.0.0.1", port=5002, debug=False)
