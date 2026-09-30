// ---------------------------------------------------------------------
// Theme toggle (persisted in localStorage)
// ---------------------------------------------------------------------
(function initTheme() {
  const saved = localStorage.getItem('securereview-theme');
  if (saved === 'dark') document.documentElement.setAttribute('data-theme', 'dark');
  document.getElementById('themeToggle').addEventListener('click', () => {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    if (isDark) {
      document.documentElement.removeAttribute('data-theme');
      localStorage.setItem('securereview-theme', 'light');
    } else {
      document.documentElement.setAttribute('data-theme', 'dark');
      localStorage.setItem('securereview-theme', 'dark');
    }
  });
})();

// ---------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------
const VIEWS = ['overview', 'workspace', 'history', 'catalog'];
function showView(name) {
  VIEWS.forEach(v => document.getElementById('view-' + v).classList.toggle('active', v === name));
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.view === name));
  if (name === 'history') loadHistory();
  if (name === 'overview') loadOverview();
}
document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => showView(t.dataset.view)));
document.querySelectorAll('[data-goto]').forEach(el => el.addEventListener('click', () => showView(el.dataset.goto)));

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}
const SEV_RANK = { critical: 3, high: 2, medium: 1, low: 0 };
const SEV_ORDER = ['critical', 'high', 'medium', 'low'];

// ---------------------------------------------------------------------
// Load sample
// ---------------------------------------------------------------------
document.getElementById('loadSampleBtn').addEventListener('click', async () => {
  const lang = document.getElementById('languageSelect').value;
  const r = await fetch('/api/sample/' + lang);
  const data = await r.json();
  document.getElementById('codeInput').value = data.code;
  document.getElementById('labelInput').value = data.label;
});

// ---------------------------------------------------------------------
// Run review
// ---------------------------------------------------------------------
document.getElementById('runReviewBtn').addEventListener('click', runReview);

async function runReview() {
  const language = document.getElementById('languageSelect').value;
  const code = document.getElementById('codeInput').value;
  const label = document.getElementById('labelInput').value;
  const statusEl = document.getElementById('workspaceStatus');
  const btn = document.getElementById('runReviewBtn');

  if (!code.trim()) {
    statusEl.className = 'status-line show err';
    statusEl.textContent = 'Paste some source code first, or click "Load sample".';
    return;
  }

  btn.disabled = true; btn.textContent = 'Reviewing…';
  statusEl.className = 'status-line';
  try {
    const r = await fetch('/api/review', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ language, code, label }),
    });
    const data = await r.json();
    if (!r.ok) {
      statusEl.className = 'status-line show err';
      statusEl.textContent = data.error || 'Review failed.';
      return;
    }
    renderReview(data);
  } catch (e) {
    statusEl.className = 'status-line show err';
    statusEl.textContent = 'Request failed — is the server running?';
  } finally {
    btn.disabled = false; btn.textContent = 'Run review';
  }
}

// ---------------------------------------------------------------------
// Render a review result into the Workspace
// ---------------------------------------------------------------------
function renderReview(entry) {
  document.getElementById('caseId').textContent = entry.id;
  document.getElementById('caseLang').textContent = entry.language === 'javascript' ? 'JavaScript' : 'Python';
  document.getElementById('caseTime').textContent = entry.timestamp;

  const lines = entry.code.split('\n');
  document.getElementById('lineCount').textContent = lines.length + ' lines';

  // line -> highest-severity finding on that line
  const byLine = {};
  entry.findings.forEach(f => {
    if (!byLine[f.line] || SEV_RANK[f.severity] > SEV_RANK[byLine[f.line].severity]) byLine[f.line] = f;
  });

  const sourceEl = document.getElementById('sourceView');
  sourceEl.innerHTML = lines.map((code, idx) => {
    const lineNo = idx + 1;
    const f = byLine[lineNo];
    const cls = f ? `flagged sev-${f.severity}` : '';
    return `<div class="source-line ${cls}" id="line-${lineNo}" title="${f ? esc(f.title) : ''}">
      <span class="ln-num">${lineNo}</span><span class="ln-code">${esc(code) || ' '}</span>
    </div>`;
  }).join('');

  const ledgerEl = document.getElementById('ledgerView');
  document.getElementById('findingCount').textContent = entry.findings.length;
  ledgerEl.innerHTML = entry.findings.length ? entry.findings.map((f, i) => `
    <div class="ledger-item" data-line="${f.line}" data-idx="${i}">
      <div class="ledger-row">
        <span class="ledger-num">${String(i + 1).padStart(2, '0')}</span>
        <span class="ledger-title">${esc(f.title)}</span>
        <span class="chip ${f.severity}">${f.severity.toUpperCase()}</span>
        <span class="ledger-line">L${f.line}</span>
      </div>
      <div class="ledger-detail">
        <div class="snip">${esc(f.snippet)}</div>
        ${f.detail ? `<div>${esc(f.detail)}</div>` : ''}
        <div class="fix"><b>Fix:</b> ${esc(f.remediation)} <span class="dim mono">(${esc(f.cwe)})</span></div>
      </div>
    </div>`).join('') : '<div class="empty-row">No findings — nothing matched the rule catalog.</div>';

  ledgerEl.querySelectorAll('.ledger-item').forEach(item => {
    item.addEventListener('click', () => {
      item.classList.toggle('open');
      const target = document.getElementById('line-' + item.dataset.line);
      if (target) {
        target.scrollIntoView({ block: 'center', behavior: 'smooth' });
        target.classList.add('jump-target');
        setTimeout(() => target.classList.remove('jump-target'), 1400);
      }
    });
  });

  // Executive summary
  document.getElementById('summaryBox').style.display = 'grid';
  document.getElementById('scoreNum').textContent = entry.score;
  const gradeEl = document.getElementById('scoreGrade');
  gradeEl.textContent = entry.grade;
  gradeEl.style.color = entry.score >= 90 ? 'var(--low)' : entry.score >= 70 ? 'var(--medium)' : entry.score >= 40 ? 'var(--high)' : 'var(--critical)';

  const counts = entry.counts;
  document.getElementById('cCritical').textContent = counts.critical;
  document.getElementById('cHigh').textContent = counts.high;
  document.getElementById('cMedium').textContent = counts.medium;
  document.getElementById('cLow').textContent = counts.low;

  const total = SEV_ORDER.reduce((a, k) => a + counts[k], 0);
  const track = document.getElementById('stackbarTrack');
  track.innerHTML = total === 0
    ? '<div class="stackbar-seg low" style="width:100%"></div>'
    : SEV_ORDER.filter(k => counts[k] > 0).map(k =>
        `<div class="stackbar-seg ${k}" style="width:${(counts[k] / total * 100).toFixed(1)}%"></div>`).join('');

  document.getElementById('summarySentence').textContent = total === 0
    ? `No findings across ${entry.total_lines} lines reviewed.`
    : `${total} finding${total === 1 ? '' : 's'} across ${entry.total_lines} lines — ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low. Estimated risk: ${entry.grade}.`;
}

// ---------------------------------------------------------------------
// Review History
// ---------------------------------------------------------------------
async function loadHistory() {
  const r = await fetch('/api/history');
  const rows = await r.json();
  const body = document.getElementById('historyBody');
  body.innerHTML = rows.length ? rows.map(h => `
    <tr>
      <td class="mono dim">${esc(h.timestamp)}</td>
      <td>${esc(h.label)}</td>
      <td>${h.language === 'javascript' ? 'JavaScript' : 'Python'}</td>
      <td class="mono">${h.score}</td>
      <td>${esc(h.grade)}</td>
      <td class="mono">${h.finding_count}</td>
      <td><span class="link-action" data-id="${h.id}">Open →</span></td>
    </tr>`).join('') : '<tr><td class="empty-row" colspan="7">No reviews yet.</td></tr>';

  body.querySelectorAll('.link-action').forEach(el => {
    el.addEventListener('click', async () => {
      const r2 = await fetch('/api/history/' + el.dataset.id);
      const entry = await r2.json();
      if (r2.ok) {
        document.getElementById('codeInput').value = entry.code;
        document.getElementById('labelInput').value = entry.label;
        document.getElementById('languageSelect').value = entry.language;
        renderReview(entry);
        showView('workspace');
      }
    });
  });
}

document.getElementById('resetHistoryLink').addEventListener('click', async () => {
  if (!confirm('Delete all review history? This cannot be undone.')) return;
  await fetch('/api/reset', { method: 'POST' });
  loadHistory();
});

// ---------------------------------------------------------------------
// Overview tab — aggregates across every review ever run
// ---------------------------------------------------------------------
async function loadOverview() {
  try {
    const r = await fetch('/api/overview');
    const d = await r.json();

    document.getElementById('ovTotalReviews').textContent = d.total_reviews;
    document.getElementById('ovTotalFindings').textContent = d.total_findings;
    document.getElementById('ovAvgScore').textContent = d.avg_score === null ? '—' : d.avg_score;
    const py = d.language_counts.python || 0, js = d.language_counts.javascript || 0;
    document.getElementById('ovLangSplit').textContent = `${py} / ${js}`;

    const topRulesEl = document.getElementById('ovTopRules');
    if (d.top_rules.length) {
      const max = Math.max(...d.top_rules.map(r => r.count));
      topRulesEl.innerHTML = d.top_rules.map(r => `
        <div class="rule-freq-row">
          <span class="chip ${r.severity}">${r.severity.toUpperCase()}</span>
          <span class="rule-freq-title">${esc(r.title)}</span>
          <div class="rule-freq-bar-track"><div class="rule-freq-bar-fill" style="width:${(r.count / max * 100).toFixed(0)}%; background:var(--${r.severity})"></div></div>
          <span class="rule-freq-count">${r.count}</span>
        </div>`).join('');
    } else {
      topRulesEl.innerHTML = '<div class="empty-row">No reviews yet — run one from the Workspace tab.</div>';
    }

    const sevTotals = d.severity_totals;
    const sevTotal = SEV_ORDER.reduce((a, k) => a + (sevTotals[k] || 0), 0);
    document.getElementById('ovSevTotal').textContent = sevTotal + ' total';
    document.getElementById('ovCritical').textContent = sevTotals.critical || 0;
    document.getElementById('ovHigh').textContent = sevTotals.high || 0;
    document.getElementById('ovMedium').textContent = sevTotals.medium || 0;
    document.getElementById('ovLow').textContent = sevTotals.low || 0;
    const track = document.getElementById('ovStackbar');
    track.innerHTML = sevTotal === 0
      ? '<div class="stackbar-seg low" style="width:100%"></div>'
      : SEV_ORDER.filter(k => sevTotals[k] > 0).map(k =>
          `<div class="stackbar-seg ${k}" style="width:${(sevTotals[k] / sevTotal * 100).toFixed(1)}%"></div>`).join('');

    const bwEl = document.getElementById('ovBestWorst');
    bwEl.textContent = d.best_review
      ? `Best score so far: "${d.best_review.label}" (${d.best_review.score}/100). Worst: "${d.worst_review.label}" (${d.worst_review.score}/100).`
      : '';

    const recentBody = document.getElementById('ovRecentBody');
    recentBody.innerHTML = d.recent.length ? d.recent.map(h => `
      <tr>
        <td class="mono dim">${esc(h.timestamp)}</td>
        <td>${esc(h.label)}</td>
        <td>${h.language === 'javascript' ? 'JavaScript' : 'Python'}</td>
        <td class="mono">${h.score}</td>
        <td>${esc(h.grade)}</td>
        <td class="mono">${h.finding_count}</td>
      </tr>`).join('') : '<tr><td class="empty-row" colspan="6">Nothing reviewed yet.</td></tr>';
  } catch (e) { /* ignore */ }
}

// ---------------------------------------------------------------------
// Rule Catalog — expandable rows
// ---------------------------------------------------------------------
document.querySelectorAll('.rule-row').forEach(row => {
  row.addEventListener('click', () => {
    row.classList.toggle('open');
    const detail = document.getElementById('rule-detail-' + row.dataset.idx);
    if (detail) detail.style.display = detail.style.display === 'none' ? 'table-row' : 'none';
  });
});

// Load the Overview tab's data once on first page load too, so switching
// to it later feels instant rather than empty-then-populated.
loadOverview();
