// The page behind /dashboard: a table of all reports with a few counts on top. It loads
// its data from /dashboard/data and builds everything with textContent, because the
// reports come from strangers.
export const DASHBOARD = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="robots" content="noindex">
<title>CSA-2026-01 reports</title>
<style>
:root {
  --bg: #f4f6f5; --surface: #fff; --surface-2: #edf1ef; --text: #17201c; --text-2: #5d6a64;
  --accent: #16774c; --border: rgba(16, 40, 30, .12); --danger: #b42318; --danger-bg: rgba(217, 45, 32, .08);
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0a0c0b; --surface: #161a18; --surface-2: #212623; --text: #f1f4f2; --text-2: #9ba6a1;
    --accent: #4cc38a; --border: rgba(255, 255, 255, .12); --danger: #ff8a7d; --danger-bg: rgba(255, 99, 85, .12);
    color-scheme: dark;
  }
}
* { box-sizing: border-box; }
body { margin: 0; padding: 24px; background: var(--bg); color: var(--text); font: 15px/1.5 -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; }
h1 { margin: 0; font-size: 24px; letter-spacing: -.02em; }
h2 { margin: 0 0 8px; font-size: 13px; font-weight: 650; color: var(--text-2); }
.sub { margin: 4px 0 20px; color: var(--text-2); }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 14px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 14px; padding: 14px 16px; min-width: 0; }
.big { font-size: 28px; font-weight: 700; letter-spacing: -.02em; }
.card ul { margin: 0; padding: 0; list-style: none; font-size: 14px; }
.card li { display: flex; justify-content: space-between; gap: 12px; padding: 2px 0; }
.card li span:first-child { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.card li span:last-child { font-variant-numeric: tabular-nums; font-weight: 650; }
.bar { margin: 20px 0 10px; display: flex; flex-wrap: wrap; gap: 10px 18px; align-items: center; font-size: 14px; }
.bar input[type=search] { flex: 1; min-width: 200px; font: inherit; padding: 8px 12px; border: 1px solid var(--border); border-radius: 10px; background: var(--surface); color: var(--text); }
.wrap { overflow-x: auto; background: var(--surface); border: 1px solid var(--border); border-radius: 14px; }
table { width: 100%; border-collapse: collapse; font-size: 13.5px; }
th { text-align: left; white-space: nowrap; padding: 10px 12px; background: var(--surface-2); font-size: 12.5px; color: var(--text-2); cursor: pointer; user-select: none; }
th[aria-sort]::after { content: ' ▾'; } th[aria-sort=ascending]::after { content: ' ▴'; }
td { padding: 10px 12px; border-top: 1px solid var(--border); vertical-align: top; }
td.n { font-variant-numeric: tabular-nums; white-space: nowrap; }
.hit { color: var(--danger); font-weight: 700; }
.chip { display: inline-block; margin: 0 4px 4px 0; padding: 1px 7px; border-radius: 6px; background: var(--surface-2); font: 12px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
tr.ioc .chip { background: var(--danger-bg); }
.mono { font: 12px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color: var(--text-2); }
.note { margin-top: 14px; font-size: 13px; color: var(--text-2); }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
</style>
</head>
<body>
<h1>CSA-2026-01 reports</h1>
<p class="sub" id="status">Loading …</p>
<div class="cards" id="cards"></div>
<div class="bar">
  <input type="search" id="q" placeholder="Filter: model, firmware, finding, hash …" aria-label="Filter">
  <label><input type="checkbox" id="onlyIoc" checked> Only with known traces</label>
  <label><input type="checkbox" id="hideTests" checked> Hide our tests</label>
</div>
<div class="wrap"><table>
  <thead><tr>
    <th data-k="received" aria-sort="descending">Received (UTC)</th><th data-k="model">Model</th><th data-k="firmware">Firmware</th>
    <th data-k="ioc">IOC</th><th data-k="persist">Persist</th><th data-k="review">Review</th>
    <th data-k="findings">Findings</th><th data-k="shell_started">Shell started</th><th data-k="ports">Port</th>
    <th data-k="uptime_s">Up since</th><th data-k="files">Files</th>
  </tr></thead>
  <tbody id="rows"></tbody>
</table></div>
<p class="note">Reports are anonymous and not verified: anyone can send one. Look for patterns, not single lines. Times are UTC. “Up since” after 20 Nov means the device was restarted after the attack, so anything that lived only in memory is gone.</p>
<script>
const $ = (id) => document.getElementById(id);
const el = (tag, text, cls) => { const e = document.createElement(tag); if (text != null) e.textContent = text; if (cls) e.className = cls; return e; };
let all = [], sortKey = 'received', asc = false;

const isTest = (r) => r.model === 'unknown' && r.platform === 'unknown' && r.ioc === 0;
const upSince = (r) => { const t = Date.parse(r.checked_at.replace(' UTC', 'Z').replace(' ', 'T')); return isNaN(t) ? '' : new Date(t - r.uptime_s * 1000).toISOString().slice(0, 16).replace('T', ' '); };
const flat = (x) => ({ ...x.report, received: x.received.slice(0, 19).replace('T', ' '), ports: (x.report.shell_ports || []).join(', '), files: x.report.files || [] });
const haystack = (r) => [r.model, r.platform, r.firmware, r.tool, r.findings.join(' '), r.shell_started, r.ports, r.files.map((f) => f.path + ' ' + f.sha256).join(' ')].join(' ').toLowerCase();

function counts(rows, key) {
  const m = new Map();
  for (const r of rows) for (const v of [].concat(key(r))) if (v) m.set(v, (m.get(v) || 0) + 1);
  return [...m].sort((a, b) => b[1] - a[1]);
}
function card(title, pairs, big) {
  const c = el('div', null, 'card'); c.append(el('h2', title));
  if (big != null) c.append(el('div', big, 'big'));
  if (pairs) { const ul = el('ul'); for (const [k, v] of pairs.slice(0, 8)) { const li = el('li'); const a = el('span', k); a.title = k; li.append(a, el('span', v)); ul.append(li); } c.append(ul); }
  return c;
}
function render() {
  const q = $('q').value.trim().toLowerCase();
  const rows = all.filter((r) => (!$('hideTests').checked || !isTest(r)) && (!$('onlyIoc').checked || r.ioc > 0) && (!q || haystack(r).includes(q)));
  const val = (r) => sortKey === 'findings' ? r.findings.length : sortKey === 'files' ? r.files.length : r[sortKey];
  rows.sort((a, b) => (val(a) > val(b) ? 1 : val(a) < val(b) ? -1 : 0) * (asc ? 1 : -1));

  const real = all.filter((r) => !isTest(r)), hit = real.filter((r) => r.ioc > 0);
  $('cards').replaceChildren(
    card('Reports with known traces', null, hit.length + ' of ' + real.length),
    card('Models (with traces)', counts(hit, (r) => r.model + ' · ' + r.platform)),
    card('Firmware (with traces)', counts(hit, (r) => r.model + ' ' + r.firmware)),
    card('Kinds of findings', counts(hit, (r) => [...new Set(r.findings.map((f) => f.split(' ').slice(0, f.startsWith('process') ? 2 : 1).join(' ')))])),
    card('Shell started (hour, UTC)', counts(hit, (r) => r.shell_started.slice(0, 13))),
    card('File hashes (same hash = same variant)', counts(hit, (r) => r.files.map((f) => f.sha256.slice(0, 12) + '… ' + f.path))),
  );

  const body = $('rows'); body.replaceChildren();
  for (const r of rows) {
    const tr = el('tr', null, r.ioc > 0 ? 'ioc' : '');
    const findings = el('td'); for (const f of r.findings) findings.append(el('span', f, 'chip'));
    const files = el('td'); for (const f of r.files) { const d = el('div', f.sha256.slice(0, 16) + '… ' + f.path + ' · ' + f.size + ' B · ' + f.mtime, 'mono'); d.title = f.sha256; files.append(d); }
    const model = el('td', r.model); model.append(el('div', r.platform + ' · script ' + r.tool, 'mono'));
    tr.append(el('td', r.received, 'n'), model, el('td', r.firmware), el('td', r.ioc, 'n' + (r.ioc > 0 ? ' hit' : '')), el('td', r.persist, 'n'), el('td', r.review, 'n'),
      findings, el('td', r.shell_started.replace(' UTC', ''), 'n'), el('td', r.ports, 'n'), el('td', upSince(r), 'n'), files);
    body.append(tr);
  }
  $('status').textContent = rows.length + ' of ' + all.length + ' reports shown';
}
for (const th of document.querySelectorAll('th')) th.addEventListener('click', () => {
  asc = sortKey === th.dataset.k ? !asc : false; sortKey = th.dataset.k;
  for (const o of document.querySelectorAll('th')) o.removeAttribute('aria-sort');
  th.setAttribute('aria-sort', asc ? 'ascending' : 'descending'); render();
});
for (const id of ['q', 'onlyIoc', 'hideTests']) $(id).addEventListener('input', render);

(async () => {
  try {
    let cursor = '';
    do {
      const res = await fetch(location.pathname.replace(/\\/$/, '') + '/data' + (cursor ? '?cursor=' + encodeURIComponent(cursor) : ''));
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const page = await res.json();
      all.push(...page.items.map(flat)); cursor = page.cursor; render();
    } while (cursor);
  } catch (e) { $('status').textContent = 'Could not load the reports: ' + e.message; }
})();
</script>
</body>
</html>
`;
