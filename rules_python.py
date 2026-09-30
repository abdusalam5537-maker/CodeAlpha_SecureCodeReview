"""
Static analysis rules for Python source.

Each rule receives the parsed module (ast.Module) and the raw source lines,
and yields Finding dicts. Rules are intentionally implemented by walking the
AST rather than pattern-matching raw text wherever possible — that's what
lets PY-SQLI tell `cursor.execute("SELECT * WHERE id=%s", (id,))` (safe,
parameterized) apart from `cursor.execute("SELECT * WHERE id=" + id)`
(unsafe, string-built), which a naive regex over the source can't.
"""

import ast
import re

RULES = {
    "PY-EVAL": {"title": "Use of eval()/exec()", "severity": "critical", "cwe": "CWE-95",
                "remediation": "Never pass untrusted input to eval()/exec(). Use ast.literal_eval() for data, or a proper parser/dispatch table for logic.",
                "impact": "Anything the caller can influence becomes arbitrary Python — full remote code execution on the host running this process.",
                "example_bad": "result = eval(request.args.get(\"expr\"))",
                "example_good": "import ast\nresult = ast.literal_eval(request.args.get(\"expr\"))"},
    "PY-CMDI": {"title": "Command Injection via shell=True", "severity": "critical", "cwe": "CWE-78",
                "remediation": "Avoid shell=True with dynamic input. Pass a list of arguments to subprocess and let the OS handle execution without a shell.",
                "impact": "An attacker can chain shell metacharacters (;, |, &&, backticks) onto the input to run arbitrary OS commands as this process's user.",
                "example_bad": "subprocess.run(f\"ping -c 1 {host}\", shell=True)",
                "example_good": "subprocess.run([\"ping\", \"-c\", \"1\", host])"},
    "PY-SQLI": {"title": "SQL Injection via string-built query", "severity": "critical", "cwe": "CWE-89",
                "remediation": "Use parameterized queries: cursor.execute(\"... WHERE id = %s\", (id,)) instead of concatenating or f-string-formatting the query.",
                "impact": "An attacker can read, modify, or delete any row in the database — or in the worst case, other databases on the same server.",
                "example_bad": "cursor.execute(\"SELECT * FROM users WHERE id=\" + user_id)",
                "example_good": "cursor.execute(\"SELECT * FROM users WHERE id=%s\", (user_id,))"},
    "PY-DESER": {"title": "Insecure Deserialization", "severity": "high", "cwe": "CWE-502",
                 "remediation": "Avoid pickle for untrusted data. For YAML, use yaml.safe_load() instead of yaml.load().",
                 "impact": "A crafted pickle/YAML payload can execute arbitrary code the moment it's loaded — no separate exploit needed.",
                 "example_bad": "config = yaml.load(uploaded_file)",
                 "example_good": "config = yaml.safe_load(uploaded_file)"},
    "PY-WEAKHASH": {"title": "Weak Hash Algorithm", "severity": "medium", "cwe": "CWE-327",
                     "remediation": "MD5/SHA-1 are broken for security purposes. Use hashlib.sha256 or, for passwords specifically, bcrypt/argon2/scrypt.",
                     "impact": "MD5/SHA-1 collisions are computationally cheap today; if used for passwords, a leaked hash database is crackable in bulk.",
                     "example_bad": "hashed = hashlib.md5(password.encode()).hexdigest()",
                     "example_good": "import bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())"},
    "PY-SECRET": {"title": "Hardcoded Secret", "severity": "high", "cwe": "CWE-798",
                   "remediation": "Load secrets from environment variables or a secrets manager (e.g. os.environ, AWS Secrets Manager) — never commit them to source.",
                   "impact": "Anyone with read access to the repository (including its full git history) can extract and reuse the credential indefinitely.",
                   "example_bad": "API_KEY = \"sk_live_51Hh2f9K3jY8m2LqW\"",
                   "example_good": "import os\nAPI_KEY = os.environ[\"API_KEY\"]"},
    "PY-DEBUG": {"title": "Debug Mode Enabled", "severity": "medium", "cwe": "CWE-489",
                 "remediation": "Never ship debug=True to production — Flask's debugger allows arbitrary code execution from the browser if reached.",
                 "impact": "If an unhandled exception is triggered, the Werkzeug debugger exposes a console that can run arbitrary Python from the browser.",
                 "example_bad": "app.run(host=\"0.0.0.0\", debug=True)",
                 "example_good": "app.run(host=\"0.0.0.0\", debug=os.environ.get(\"FLASK_DEBUG\") == \"1\")"},
    "PY-RANDOM": {"title": "Insecure Randomness for Security Token", "severity": "medium", "cwe": "CWE-330",
                  "remediation": "random is not cryptographically secure. Use the secrets module (secrets.token_urlsafe(), secrets.token_hex()) for tokens, session IDs, or passwords.",
                  "impact": "random's output is predictable from a handful of samples, letting an attacker guess or brute-force future session tokens.",
                  "example_bad": "session_id = str(random.random())",
                  "example_good": "import secrets\nsession_id = secrets.token_urlsafe(32)"},
    "PY-ASSERT": {"title": "Security Check via assert", "severity": "medium", "cwe": "CWE-617",
                  "remediation": "assert statements are stripped when Python runs with -O. Use an explicit if/raise for anything security-relevant (auth, permissions).",
                  "impact": "Running the interpreter with -O silently deletes this check entirely, turning a permission gate into a no-op with no warning.",
                  "example_bad": "assert user.is_admin, \"not authorized\"",
                  "example_good": "if not user.is_admin:\n    raise PermissionError(\"not authorized\")"},
    "PY-TLSVERIFY": {"title": "TLS Certificate Verification Disabled", "severity": "high", "cwe": "CWE-295",
                      "remediation": "Never set verify=False in production. If a custom CA is needed, pass verify='/path/to/ca-bundle.pem' instead.",
                      "impact": "Any network position (public wifi, a compromised router) can now intercept and rewrite this traffic via a trivial MITM.",
                      "example_bad": "requests.get(url, verify=False)",
                      "example_good": "requests.get(url, verify=\"/etc/ssl/certs/ca-bundle.pem\")"},
    "PY-REDIRECT": {"title": "Open Redirect", "severity": "medium", "cwe": "CWE-601",
                     "remediation": "Validate that redirect targets are relative paths or match an allow-list of known hosts before calling redirect().",
                     "impact": "Attackers craft a link on your trusted domain that bounces the victim to a phishing site, borrowing your domain's credibility.",
                     "example_bad": "return redirect(request.args.get(\"next\"))",
                     "example_good": "next_url = request.args.get(\"next\", \"/\")\nif not next_url.startswith(\"/\"):\n    next_url = \"/\"\nreturn redirect(next_url)"},
    "PY-TEMPLATEXSS": {"title": "Template Injection / XSS via render_template_string", "severity": "high", "cwe": "CWE-79",
                        "remediation": "Never build a template string from user input. Use render_template() with a static template file and pass data as context variables (auto-escaped).",
                        "impact": "User input is compiled as a Jinja2 template, not just displayed — this can escalate past XSS to full server-side template injection (SSTI).",
                        "example_bad": "return render_template_string(\"<h1>Hello \" + name + \"</h1>\")",
                        "example_good": "return render_template(\"greet.html\", name=name)  # auto-escaped"},
    "PY-BAREEXCEPT": {"title": "Silent Exception Swallowing", "severity": "low", "cwe": "CWE-390",
                       "remediation": "Catch specific exceptions and log them. A bare `except: pass` can hide security-relevant failures (e.g. a failed permission check).",
                       "impact": "A failed auth check, a failed write, or a security-relevant error disappears silently — the code keeps running as if it succeeded.",
                       "example_bad": "try:\n    check_permission(user)\nexcept:\n    pass",
                       "example_good": "try:\n    check_permission(user)\nexcept PermissionError:\n    logger.warning(\"denied: %s\", user.id)\n    raise"},
    "PY-COOKIE": {"title": "Cookie Missing Secure/HttpOnly Flags", "severity": "medium", "cwe": "CWE-614",
                   "remediation": "Set secure=True and httponly=True on any cookie carrying a session token or sensitive value.",
                   "impact": "Without HttpOnly, a single XSS bug anywhere on the site can steal this cookie via JavaScript; without Secure, it can leak over plain HTTP.",
                   "example_bad": "response.set_cookie(\"session\", session_id)",
                   "example_good": "response.set_cookie(\"session\", session_id, secure=True, httponly=True, samesite=\"Lax\")"},
    "PY-CORS": {"title": "Permissive CORS Policy", "severity": "medium", "cwe": "CWE-942",
                "remediation": "Avoid Access-Control-Allow-Origin: *  for endpoints that require credentials. Echo back a specific, validated origin instead.",
                "impact": "Any website the victim visits can call this API from the victim's browser and read the response, bypassing the same-origin policy.",
                "example_bad": "response.headers[\"Access-Control-Allow-Origin\"] = \"*\"",
                "example_good": "if origin in ALLOWED_ORIGINS:\n    response.headers[\"Access-Control-Allow-Origin\"] = origin"},
}

SECRET_NAME_RE = re.compile(r"(password|passwd|pwd|secret|api[_-]?key|apikey|token|access[_-]?key)", re.I)
SECURITY_COND_RE = re.compile(r"(is_admin|authenticated|has_permission|permission|authorized)", re.I)
TOKEN_VAR_RE = re.compile(r"(token|session|password|otp)", re.I)


def _src(node, lines):
    try:
        return lines[node.lineno - 1].strip()
    except Exception:
        return ""


def _finding(rule_id, node, lines, detail=None):
    rule = RULES[rule_id]
    return {
        "rule_id": rule_id,
        "title": rule["title"],
        "severity": rule["severity"],
        "cwe": rule["cwe"],
        "remediation": rule["remediation"],
        "impact": rule["impact"],
        "line": getattr(node, "lineno", 0),
        "snippet": _src(node, lines),
        "detail": detail or "",
    }


def _call_name(node):
    """Best-effort dotted name for a Call node's func, e.g. 'subprocess.run'."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts = []
        cur = node.func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _is_dynamic_string(node):
    """True if this AST node builds a string dynamically (f-string, concat, %-format)
    rather than being a plain constant — the SQL-injection-shaped pattern."""
    if isinstance(node, ast.JoinedStr):  # f-string
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call):
        name = _call_name(node)
        if name in ("format",) or name.endswith(".format"):
            return True
    return False


def _kwarg(call_node, name):
    for kw in call_node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _iter_source_order(node):
    """Pre-order DFS, unlike ast.walk's BFS — keeps statements in the order
    they appear in the file, which the SQLI variable-tracking below relies on."""
    yield node
    for child in ast.iter_child_nodes(node):
        yield from _iter_source_order(child)


def analyze(source):
    lines = source.splitlines()
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return [], f"Could not parse source: {e}"

    findings = []
    dynamic_string_vars = {}  # var name -> the line where it was built, for lightweight taint tracking
    request_derived_vars = {}  # var name -> line, for values that came straight from request.*
    current_function = ""  # best-effort enclosing function name, for the PY-RANDOM heuristic below

    for node in _iter_source_order(tree):
        if isinstance(node, ast.FunctionDef):
            current_function = node.name

        # Track "var = <dynamically built string>" so a later execute()/render_template_string(var)
        # call can be traced back to it, and "var = request.args/form/values[...]" for redirect().
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if _is_dynamic_string(node.value):
                dynamic_string_vars[node.targets[0].id] = _src(node, lines)
            value_dump = ast.dump(node.value)
            if "request" in value_dump and any(k in value_dump for k in ("args", "form", "values")):
                request_derived_vars[node.targets[0].id] = _src(node, lines)
        if isinstance(node, ast.Call):
            name = _call_name(node)

            # PY-EVAL
            if name in ("eval", "exec"):
                findings.append(_finding("PY-EVAL", node, lines))

            # PY-CMDI
            if name in ("os.system",):
                findings.append(_finding("PY-CMDI", node, lines, "os.system executes via the shell unconditionally."))
            if name in ("subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output"):
                shell_kw = _kwarg(node, "shell")
                if isinstance(shell_kw, ast.Constant) and shell_kw.value is True:
                    findings.append(_finding("PY-CMDI", node, lines, f"{name}(..., shell=True)"))

            # PY-SQLI
            if name.endswith(".execute") or name.endswith(".executemany"):
                if node.args and _is_dynamic_string(node.args[0]):
                    findings.append(_finding("PY-SQLI", node, lines, "Query string is built with concatenation/f-string/%% instead of parameter placeholders."))
                elif node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in dynamic_string_vars:
                    built_at = dynamic_string_vars[node.args[0].id]
                    findings.append(_finding("PY-SQLI", node, lines, f"'{node.args[0].id}' is built dynamically earlier ({built_at}) then passed to execute() unparameterized."))

            # PY-DESER
            if name in ("pickle.loads", "pickle.load"):
                findings.append(_finding("PY-DESER", node, lines, "pickle can execute arbitrary code when loading untrusted data."))
            if name == "yaml.load":
                loader_kw = _kwarg(node, "Loader")
                safe = loader_kw is not None and "SafeLoader" in ast.dump(loader_kw)
                if not safe:
                    findings.append(_finding("PY-DESER", node, lines, "yaml.load() without Loader=SafeLoader."))

            # PY-WEAKHASH
            if name in ("hashlib.md5", "hashlib.sha1"):
                findings.append(_finding("PY-WEAKHASH", node, lines, f"{name}() used — cryptographically broken."))

            # PY-DEBUG
            if name.endswith(".run"):
                debug_kw = _kwarg(node, "debug")
                if isinstance(debug_kw, ast.Constant) and debug_kw.value is True:
                    findings.append(_finding("PY-DEBUG", node, lines))

            # PY-RANDOM
            if name in ("random.random", "random.randint", "random.choice", "random.randrange"):
                # heuristic: flag if this line or its enclosing function name mentions a
                # security-sensitive term (e.g. generate_session_token() -> random.random())
                ctx = _src(node, lines)
                if TOKEN_VAR_RE.search(ctx) or TOKEN_VAR_RE.search(current_function):
                    findings.append(_finding("PY-RANDOM", node, lines, f"'{ctx}' inside {current_function}() — random is not suitable for security tokens."))

            # PY-TLSVERIFY
            if name in ("requests.get", "requests.post", "requests.put", "requests.delete", "requests.request"):
                verify_kw = _kwarg(node, "verify")
                if isinstance(verify_kw, ast.Constant) and verify_kw.value is False:
                    findings.append(_finding("PY-TLSVERIFY", node, lines))

            # PY-REDIRECT
            if name in ("redirect",) and node.args:
                arg = node.args[0]
                arg_src = ast.dump(arg)
                direct = "request" in arg_src and any(k in arg_src for k in ("args", "form", "values"))
                via_var = isinstance(arg, ast.Name) and arg.id in request_derived_vars
                if direct or via_var:
                    detail = "Redirect target comes directly from request parameters." if direct \
                        else f"'{arg.id}' was set from a request parameter earlier ({request_derived_vars.get(arg.id, '') if via_var else ''})."
                    findings.append(_finding("PY-REDIRECT", node, lines, detail))

            # PY-TEMPLATEXSS
            if name in ("render_template_string",) and node.args:
                arg = node.args[0]
                if _is_dynamic_string(arg) or (isinstance(arg, ast.Name) and arg.id in dynamic_string_vars):
                    findings.append(_finding("PY-TEMPLATEXSS", node, lines))

        # PY-SECRET — Assign where the target name looks sensitive and the value is a literal string
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and SECRET_NAME_RE.search(target.id):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and len(node.value.value) >= 4:
                        findings.append(_finding("PY-SECRET", node, lines, f"{target.id} = \"...\" (literal string assigned to a credential-shaped name)"))

        # PY-ASSERT — assert on a security-shaped condition
        if isinstance(node, ast.Assert):
            cond_src = _src(node, lines)
            if SECURITY_COND_RE.search(cond_src):
                findings.append(_finding("PY-ASSERT", node, lines, cond_src))

        # PY-BAREEXCEPT
        if isinstance(node, ast.ExceptHandler):
            if node.type is None and len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                findings.append(_finding("PY-BAREEXCEPT", node, lines))

    # Line-scan rules — patterns that are more naturally text-shaped than AST-shaped
    def _line_finding(rule_id, i, line, detail):
        r = RULES[rule_id]
        return {"rule_id": rule_id, "title": r["title"], "severity": r["severity"], "cwe": r["cwe"],
                "remediation": r["remediation"], "impact": r["impact"], "line": i, "snippet": line.strip(), "detail": detail}

    for i, line in enumerate(lines, start=1):
        if re.search(r"set_cookie\(", line) and "session" in line.lower():
            if "secure=True" not in line or "httponly=True" not in line:
                findings.append(_line_finding("PY-COOKIE", i, line, "Missing secure=True and/or httponly=True."))
        if re.search(r"Access-Control-Allow-Origin.{0,10}[\"']\*[\"']", line):
            findings.append(_line_finding("PY-CORS", i, line, "Wildcard origin."))

    findings.sort(key=lambda f: f["line"])
    return findings, None
