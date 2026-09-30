# Secure Code Review

Built for **CodeAlpha Cyber Security Internship — Task 3**, alongside
PhishGuard (Task 2) and NetGuard (Task 4). Deliberately not styled like
either of those two — this one reads as an audit report and reference
catalog rather than a live-monitoring dashboard, because that's what a
code review actually produces.

## What it does

You paste (or load a sample of) Python or JavaScript source. It's run
through a real static analyzer — not a lookup table of canned results —
and every match becomes a finding with a line number, a severity, a CWE
reference, and a plain-English fix.

**Python** is checked by walking the actual `ast` (abstract syntax tree),
which is why it can tell `cursor.execute("... WHERE id=%s", (id,))`
(parameterized, safe) apart from `cursor.execute("... WHERE id=" + id)`
(string-built, SQL injection) — a regex over the text can't make that
distinction, but a parser can. It also does light variable tracking: if a
query string is built on one line and passed to `.execute()` a few lines
later, or a redirect target is pulled from `request.args` into a variable
first, it still gets flagged.

**JavaScript** is checked with a smaller, deliberately conservative set of
regex-based rules — real JS analysis needs a real parser (e.g. Esprima/
Acorn), which is out of scope for a from-scratch internship project, so
the JS rules are written to minimize false positives rather than to be
exhaustive. That tradeoff is documented, not hidden.

## The 15 Python + 9 JavaScript checks

See the **Rule Catalog** tab in the app for the full list with CWE
references and remediation text. Categories covered: injection (SQL,
command, template), insecure deserialization, weak cryptography and
randomness, hardcoded secrets, disabled TLS verification, open redirects,
permissive CORS, insecure cookies, silent exception handling, and a few
JS-specific ones (unsafe `innerHTML`, JWT `alg: none`).

## Known limitations (stated up front, like a real audit would)

- No taint tracking across function boundaries or file boundaries — only
  within a single function/module scope.
- The JavaScript ruleset is text-pattern-based, not AST-based, so it will
  miss vulnerabilities that don't match one of the 9 patterns and can, in
  unusual formatting, produce a false positive or negative.
- This tool finds *known vulnerability shapes*. It is not a substitute for
  a human review, a real SAST tool (Semgrep, Bandit, CodeQL) run in CI, or
  a professional penetration test.

## Dashboard structure

- **Overview** — aggregated stats across *every* review ever run on this
  instance, not just the one open in the Workspace: total reviews, total
  findings logged, average security score, a Python/JavaScript split, the
  most frequently triggered rules ranked by count, all-time findings by
  severity, and the best/worst-scoring review so far. This is the
  audit-engagement-level view — what a reviewer would want after running
  the tool against several files, not just one.
- **Workspace** — paste code (or load a bundled vulnerable sample),
  run the review, and see the source annotated in place: every flagged
  line gets a colored left border in the severity's color. The Findings
  Ledger next to it lists every match in order, click one to jump to its
  line and expand the fix. Below both, an Executive Summary gives a 0–100
  security score, a risk grade, and a stacked bar of findings by severity.
- **Review History** — every review ever run, persisted to
  `data/history.json`, not just today's count. Click a row to reopen that
  exact review (code + findings) back into the Workspace.
- **Rule Catalog** — every check the tool runs, in both languages. Click
  a row to expand it: the vulnerable pattern and its fix shown side by
  side, plus the CWE reference and a plain-English explanation of the
  actual impact — useful both as in-app documentation and as the
  "recommendations and best practices" writeup the task asks for.
- **Dark theme** — 🌙 toggle in the masthead, persisted in `localStorage`.
  Every surface (panes, chips, code blocks, tables) is theme-aware via CSS
  variables, not just the page background.

## Running it

```bash
pip install -r requirements.txt
python app.py
```

Open **http://localhost:5002** (PhishGuard uses 5000, NetGuard uses 5001,
so all three can run at once).

Click **Load sample** then **Run review** to see it work immediately
against `samples/vulnerable_sample.py` (16 findings) or
`samples/vulnerable_sample.js` (9 findings) — both are bundled,
intentionally vulnerable files written specifically to exercise every
rule in the catalog, so they're a good basis for your video walkthrough.

## Internship task checklist

This satisfies **Task 3: Secure Coding Review**:
- ✅ Select a programming language and application to audit — Python and
  JavaScript, either your own file or the bundled vulnerable samples
- ✅ Perform a code review to identify security vulnerabilities — 24 rules
  across both languages, real AST parsing for Python
- ✅ Use tools like static analyzers or manual inspection methods — this
  *is* a static analyzer, built from scratch rather than wrapping an
  existing one
- ✅ Provide recommendations and best practices for secure coding — every
  finding carries a specific remediation, not just a severity label
- ✅ Document findings and suggest remediation steps — the Findings Ledger
  and Review History together are that documentation, and they're
  persisted so you can revisit or export them later
