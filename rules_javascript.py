"""
Static analysis rules for JavaScript/TypeScript source.

Line-scan/regex based — JS/TS parsing without a real parser is inherently
looser than the Python ast-based engine, so these rules are written to
minimize false positives (matching the risky *shape* of a call, not just
a keyword) rather than to be exhaustive.
"""

import re

RULES = {
    "JS-EVAL": {"title": "Use of eval() / new Function()", "severity": "critical", "cwe": "CWE-95",
                "remediation": "Never eval() untrusted input. Use JSON.parse() for data, or a proper parser for anything else.",
                "impact": "Anything the caller can influence becomes arbitrary JavaScript — full code execution in whatever context this runs (browser tab or Node process).",
                "example_bad": "const result = eval(req.query.expr);",
                "example_good": "const result = JSON.parse(req.query.expr); // only if expr is meant to be data"},
    "JS-CMDI": {"title": "Command Injection via child_process", "severity": "critical", "cwe": "CWE-78",
                "remediation": "Use execFile()/spawn() with an argument array instead of exec() with a built string, so the shell never re-interprets user input.",
                "impact": "An attacker can chain shell metacharacters onto the input to run arbitrary OS commands as the Node process's user.",
                "example_bad": "exec(`ping -c 1 ${host}`);",
                "example_good": "execFile(\"ping\", [\"-c\", \"1\", host]);"},
    "JS-INNERHTML": {"title": "Unsanitized innerHTML Assignment (XSS)", "severity": "high", "cwe": "CWE-79",
                      "remediation": "Use textContent for plain text, or sanitize with a library like DOMPurify before assigning HTML built from user input.",
                      "impact": "An attacker-controlled <script> or event handler runs in the victim's browser session, with access to cookies, storage, and the page's DOM.",
                      "example_bad": "el.innerHTML = \"<p>Results for \" + term + \"</p>\";",
                      "example_good": "el.textContent = `Results for ${term}`;"},
    "JS-DOCWRITE": {"title": "document.write() with dynamic content", "severity": "medium", "cwe": "CWE-79",
                     "remediation": "Avoid document.write(); render into the DOM with textContent/createElement instead.",
                     "impact": "Same outcome as unsanitized innerHTML — attacker-controlled markup is parsed and executed in the page.",
                     "example_bad": "document.write(\"<h1>Welcome \" + name + \"</h1>\");",
                     "example_good": "document.getElementById(\"greeting\").textContent = `Welcome ${name}`;"},
    "JS-SECRET": {"title": "Hardcoded Secret", "severity": "high", "cwe": "CWE-798",
                   "remediation": "Load secrets from environment variables (process.env) or a secrets manager — never commit them to source.",
                   "impact": "Anyone with read access to the repository (including its git history, or the shipped client bundle) can extract and reuse the credential.",
                   "example_bad": "const API_SECRET = \"sk_live_9fJ2kLp0qR7mZ8x\";",
                   "example_good": "const API_SECRET = process.env.API_SECRET;"},
    "JS-JWTNONE": {"title": "JWT Algorithm 'none' Accepted", "severity": "critical", "cwe": "CWE-347",
                    "remediation": "Explicitly allow-list the expected signing algorithm (e.g. ['HS256']) and never include 'none'.",
                    "impact": "An attacker can forge a token with alg: none and no signature at all, and the app will accept it as valid — full auth bypass.",
                    "example_bad": "jwt.verify(token, secret, { algorithms: [\"HS256\", \"none\"] });",
                    "example_good": "jwt.verify(token, secret, { algorithms: [\"HS256\"] });"},
    "JS-WEAKRANDOM": {"title": "Insecure Randomness for Security Token", "severity": "medium", "cwe": "CWE-330",
                        "remediation": "Math.random() is not cryptographically secure. Use crypto.randomBytes() / crypto.getRandomValues() for tokens or session IDs.",
                        "impact": "Math.random()'s internal state can be inferred from a handful of outputs, letting an attacker predict future session IDs.",
                        "example_bad": "const sessionId = \"sess_\" + Math.random().toString(36);",
                        "example_good": "const sessionId = \"sess_\" + crypto.randomBytes(16).toString(\"hex\");"},
    "JS-CORS": {"title": "Permissive CORS Policy", "severity": "medium", "cwe": "CWE-942",
                "remediation": "Avoid Access-Control-Allow-Origin: '*' for endpoints that require credentials. Echo back a specific, validated origin instead.",
                "impact": "Any website the victim visits can call this API from the victim's browser and read the response, bypassing the same-origin policy.",
                "example_bad": "res.header(\"Access-Control-Allow-Origin\", \"*\");",
                "example_good": "if (ALLOWED_ORIGINS.includes(origin)) res.header(\"Access-Control-Allow-Origin\", origin);"},
    "JS-INSECUREURL": {"title": "Hardcoded Insecure HTTP Endpoint", "severity": "low", "cwe": "CWE-319",
                         "remediation": "Use https:// for any endpoint carrying credentials, tokens, or personal data.",
                         "impact": "Traffic to this endpoint can be read or altered by anyone on the network path — no interception skill beyond packet capture needed.",
                         "example_bad": "fetch(\"http://payments.internal.example/status\");",
                         "example_good": "fetch(\"https://payments.internal.example/status\");"},
}

SECRET_NAME_RE = re.compile(r"(password|passwd|pwd|secret|api[_-]?key|apikey|token|accesskey)", re.I)
LITERAL_ASSIGN_RE = re.compile(r"(?:const|let|var)\s+([A-Za-z0-9_]+)\s*=\s*[\"']([^\"']{4,})[\"']")
TOKEN_VAR_RE = re.compile(r"(token|session|password|otp)", re.I)


def _finding(rule_id, line_no, line, detail=""):
    r = RULES[rule_id]
    return {
        "rule_id": rule_id, "title": r["title"], "severity": r["severity"], "cwe": r["cwe"],
        "remediation": r["remediation"], "impact": r["impact"], "line": line_no, "snippet": line.strip(), "detail": detail,
    }


def analyze(source):
    lines = source.splitlines()
    findings = []
    current_function = ""  # best-effort enclosing function name, for the weak-random heuristic

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        if re.search(r"\beval\s*\(", line) or re.search(r"new\s+Function\s*\(", line):
            findings.append(_finding("JS-EVAL", i, line))

        if re.search(r"\bexec\s*\(\s*`", line) or (re.search(r"\bexec\s*\(", line) and "+" in line):
            findings.append(_finding("JS-CMDI", i, line, "child_process.exec() called with a built/template string."))

        m_html = re.search(r"\.innerHTML\s*=\s*(.+?);?\s*$", line)
        if m_html and not re.match(r'^[\"\'`][^\"\'`]*[\"\'`]$', m_html.group(1).strip()):
            findings.append(_finding("JS-INNERHTML", i, line))

        m_dw = re.search(r"document\.write\s*\((.+)\)\s*;?\s*$", line)
        if m_dw and not re.match(r'^[\"\'][^\"\']*[\"\']$', m_dw.group(1).strip()):
            findings.append(_finding("JS-DOCWRITE", i, line))

        m = LITERAL_ASSIGN_RE.search(line)
        if m and SECRET_NAME_RE.search(m.group(1)):
            findings.append(_finding("JS-SECRET", i, line, f"{m.group(1)} = \"...\" (literal string assigned to a credential-shaped name)"))

        if re.search(r"algorithms?\s*:\s*\[[^\]]*[\"']none[\"']", line, re.I):
            findings.append(_finding("JS-JWTNONE", i, line))

        fn_match = re.search(r"function\s+(\w+)\s*\(", line)
        if fn_match:
            current_function = fn_match.group(1)
        if "Math.random(" in line and (TOKEN_VAR_RE.search(line) or TOKEN_VAR_RE.search(current_function)):
            findings.append(_finding("JS-WEAKRANDOM", i, line, f"inside {current_function}()" if current_function else ""))

        if re.search(r"Access-Control-Allow-Origin.{0,10}[\"']\*[\"']", line):
            findings.append(_finding("JS-CORS", i, line))

        m2 = re.search(r"[\"']http://[^\"'\s]+[\"']", line)
        if m2 and "localhost" not in m2.group(0) and "127.0.0.1" not in m2.group(0):
            findings.append(_finding("JS-INSECUREURL", i, line))

    findings.sort(key=lambda f: f["line"])
    return findings, None
