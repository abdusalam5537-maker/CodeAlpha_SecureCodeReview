"""
Ties a language to its rule module and turns raw findings into the
executive-summary numbers the dashboard shows (score, grade, counts).
"""

import rules_python
import rules_javascript

SEVERITY_WEIGHT = {"critical": 22, "high": 12, "medium": 6, "low": 2}
SEVERITY_ORDER = ["critical", "high", "medium", "low"]

LANGUAGES = {
    "python": {"label": "Python", "module": rules_python, "extensions": [".py"]},
    "javascript": {"label": "JavaScript", "module": rules_javascript, "extensions": [".js", ".ts", ".jsx", ".tsx"]},
}


def all_rules():
    """Rule catalog across every supported language, tagged with which language it belongs to."""
    catalog = []
    for lang_key, lang in LANGUAGES.items():
        for rule_id, rule in lang["module"].RULES.items():
            catalog.append({"language": lang["label"], "rule_id": rule_id, **rule})
    return catalog


def score_from_findings(findings):
    penalty = sum(SEVERITY_WEIGHT.get(f["severity"], 0) for f in findings)
    score = max(0, 100 - penalty)
    if score >= 90:
        grade = "Low Risk"
    elif score >= 70:
        grade = "Moderate Risk"
    elif score >= 40:
        grade = "High Risk"
    else:
        grade = "Critical Risk"
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        if f["severity"] in counts:
            counts[f["severity"]] += 1
    return score, grade, counts


def analyze(language, source):
    if language not in LANGUAGES:
        return None, f"Unsupported language '{language}'."
    module = LANGUAGES[language]["module"]
    findings, err = module.analyze(source)
    if err:
        return None, err
    score, grade, counts = score_from_findings(findings)
    return {
        "findings": findings,
        "score": score,
        "grade": grade,
        "counts": counts,
        "total_lines": len(source.splitlines()),
    }, None
