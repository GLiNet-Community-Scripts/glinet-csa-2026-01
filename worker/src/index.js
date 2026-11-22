// Collects the short, anonymous reports that gl-helper-triage.sh sends when its user
// agrees. One report is a few facts about a device (model, firmware, which indicators
// were found, when). The worker stores exactly the fields listed below and nothing
// about the sender: no IP address, no country, no headers.

import { DASHBOARD } from './dashboard.js';

const MAX_BYTES = 49152;
const SAFE = /^[A-Za-z0-9 ._:\/+@=,()-]*$/;
const TIME = /^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC)?$/;

const str = (max) => (v) => typeof v === 'string' && v.length <= max && SAFE.test(v);
const int = (v) => Number.isInteger(v) && v >= 0 && v <= 1e9;
const time = (v) => typeof v === 'string' && TIME.test(v);
const list = (max, item) => (v) => Array.isArray(v) && v.length <= max && v.every(item);

// Every field is required; anything else in a report is refused.
const FIELDS = {
  schema: (v) => v === 1 || v === 2 || v === 3 || v === 4 || v === 5 || v === 6 || v === 7,
  tool: str(16),
  platform: str(48),
  model: str(64),
  firmware: str(48),
  checked_at: time,
  uptime_s: int,
  ioc: int,
  persist: int,
  review: int,
  findings: list(40, str(120)),
  quick_check: (v) => typeof v === 'boolean',
  shell_started: time,
  shell_ports: list(10, (v) => Number.isInteger(v) && v > 0 && v < 65536),
  pipe_time: time,
};

// Since script 2.2 (schema 2): fingerprints of the implant's files and the time of the
// cloud handler's state file.
const FILE = { path: str(120), sha256: (v) => typeof v === 'string' && /^([0-9a-f]{64})?$/.test(v), size: int, mtime: time };
const isFileOf = (shape) => (v) =>
  v !== null && typeof v === 'object' && !Array.isArray(v) &&
  Object.keys(v).length === Object.keys(shape).length && Object.entries(shape).every(([k, ok]) => ok(v[k]));
const isFile = isFileOf(FILE);
const FIELDS_V2 = { ...FIELDS, state_file_time: time, files: list(12, isFile) };

// Since script 2.3 (schema 3): what the attacker left, as free text: changed lines of
// autostart files, the rules of the firewall chain the attack used, command lines of its
// processes. Printable ASCII only; the dashboard shows it as text, never as HTML.
const txt = (max) => (v) => typeof v === 'string' && v.length <= max && /^[\x20-\x7e]*$/.test(v);
const isPersist = (v) =>
  v !== null && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === 2 &&
  str(120)(v.path) && list(60, txt(300))(v.lines);
const FIELDS_V3 = { ...FIELDS_V2, persistence: list(6, isPersist), fw_rules: list(10, txt(300)), commands: list(5, txt(400)) };

// Since script 2.9 (schema 4): a device id, so that repeated reports from one device can
// be told apart from reports of many devices. The script sends a hash of a hardware
// address. A plain hash of a MAC address can be reversed by trying all addresses, so the
// worker never stores what it receives: it stores an HMAC of it with the secret
// DEVICE_SALT, shortened. Without that secret the id is dropped.
const FIELDS_V4 = { ...FIELDS_V3, device_id: (v) => typeof v === 'string' && /^([0-9a-f]{16})?$/.test(v) };

// Since script 2.13 (schema 5): each file also carries its ctime, the time the kernel last
// changed the file's entry. touch and tar can set the written time back, not this one.
const FIELDS_V5 = { ...FIELDS_V4, files: list(12, isFileOf({ ...FILE, ctime: time })) };

// Since script 2.23 (schema 6): what the script listed for review, as kind and path with
// a fingerprint for files, so that a pattern across devices shows up; whether GoodCloud
// and AstroWarp are switched on; and the size of the cloud handler's state file (-1: no
// such file). An empty state file is what the attack leaves.
const onoff = (v) => v === 'on' || v === 'off' || v === 'unknown';
const isReview = isFileOf({ kind: str(24), path: str(160), sha256: FILE.sha256 });
const FIELDS_V6 = {
  ...FIELDS_V5, goodcloud: onoff, cloud_client: str(32), astrowarp: onoff,
  state_file_size: (v) => Number.isInteger(v) && v >= -1 && v <= 1e9, review_items: list(40, isReview),
};

// Since script 2.24 (schema 7): each review item also carries its two times, as the files
// of the malware do: when it was written and when the kernel last changed its entry.
const FIELDS_V7 = { ...FIELDS_V6, review_items: list(40, isFileOf({ kind: str(24), path: str(160), sha256: FILE.sha256, mtime: time, ctime: time })) };

async function sealDeviceId(env, id) {
  if (!env.DEVICE_SALT || !id) return '';
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.DEVICE_SALT), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(id)));
  return [...mac.slice(0, 6)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

const text = (body, status = 200) =>
  new Response(body + '\n', { status, headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' } });

export function validate(report) {
  if (report === null || typeof report !== 'object' || Array.isArray(report)) return 'not an object';
  const fields = report.schema === 7 ? FIELDS_V7 : report.schema === 6 ? FIELDS_V6 : report.schema === 5 ? FIELDS_V5 : report.schema === 4 ? FIELDS_V4 : report.schema === 3 ? FIELDS_V3 : report.schema === 2 ? FIELDS_V2 : FIELDS;
  for (const key of Object.keys(report)) if (!(key in fields)) return `unknown field ${key.slice(0, 32)}`;
  for (const [key, ok] of Object.entries(fields)) if (!ok(report[key])) return `bad or missing field ${key}`;
  return null;
}

// ---------------------------------------------------------------- storage
// Reports live in D1 (a table, one row per report) when the binding DB exists, and in KV
// as before when it does not, so the worker can be deployed before the database is set
// up. D1 fits the job better: one write per report, the whole dashboard in a few
// queries, and no daily limit of 1,000 writes and listings.
const LATEST_KEY = 'meta/csa-2026-01-latest';
// On the free Workers plan one request may make 50 subrequests, and every KV read is one.
// From KV, reports are therefore handed out 40 at a time. A D1 query is one subrequest.
const PAGE = 40;
const DB_PAGE = 500;
const row = (r) => ({ id: r.id, received: r.received, report: JSON.parse(r.report) });
const kvLoad = async (env, names) =>
  (await Promise.all(names.map(async (name) => [name, await env.REPORTS.get(name)]))).filter((x) => x[1]).map(([id, v]) => ({ id, ...JSON.parse(v) }));

// What the team says about a finding that the scripts listed for review: "probably safe",
// with a note. The dashboard then hides it unless asked. Everyone who may open the
// dashboard may set and remove a label, and each label records who set it (the address
// Cloudflare Access signed in). One label per kind and path; it remembers the fingerprints it
// was given for, so a new file at a path that was called harmless shows up again.
// Kept in D1 (the table is created on first use) or, without D1, in one KV entry.
const LABELS_KEY = 'meta/csa-2026-01-labels';
let labelsTable = false;
const labels = {
  async ready(env) {
    if (labelsTable) return;
    await env.DB.prepare('CREATE TABLE IF NOT EXISTS labels (key TEXT PRIMARY KEY, verdict TEXT NOT NULL, note TEXT NOT NULL, hashes TEXT NOT NULL, by TEXT NOT NULL, at TEXT NOT NULL)').run();
    labelsTable = true;
  },
  async all(env) {
    if (env.DB) {
      await labels.ready(env);
      const { results } = await env.DB.prepare('SELECT key, verdict, note, hashes, by, at FROM labels').all();
      return Object.fromEntries(results.map((r) => [r.key, { verdict: r.verdict, note: r.note, hashes: JSON.parse(r.hashes), by: r.by, at: r.at }]));
    }
    return JSON.parse((await env.REPORTS.get(LABELS_KEY)) || '{}');
  },
  async set(env, key, label) {
    if (env.DB) {
      await labels.ready(env);
      if (!label) await env.DB.prepare('DELETE FROM labels WHERE key = ?1').bind(key).run();
      else await env.DB.prepare('INSERT OR REPLACE INTO labels (key, verdict, note, hashes, by, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)').bind(key, label.verdict, label.note, JSON.stringify(label.hashes), label.by, label.at).run();
      return;
    }
    const all = JSON.parse((await env.REPORTS.get(LABELS_KEY)) || '{}');
    if (label) all[key] = label; else delete all[key];
    await env.REPORTS.put(LABELS_KEY, JSON.stringify(all));
  },
};

// A label as the dashboard sends it. The key is a kind and a path as the reports carry
// them; the note is plain text and shown as text.
export function validLabel(body) {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return 'not an object';
  if (!(typeof body.key === 'string' && body.key.length >= 3 && body.key.length <= 200 && SAFE.test(body.key))) return 'bad key';
  if (!['safe', ''].includes(body.verdict)) return 'bad verdict';
  if (!(typeof body.note === 'string' && body.note.length <= 200 && /^[\x20-\x7e]*$/.test(body.note))) return 'bad note';
  if (!(Array.isArray(body.hashes) && body.hashes.length <= 60 && body.hashes.every((h) => typeof h === 'string' && /^[0-9a-f]{64}$/.test(h)))) return 'bad hashes';
  return null;
}

const reports = {
  async add(env, received, report) {
    if (env.DB) {
      await env.DB.prepare('INSERT INTO reports (id, received, report) VALUES (?1, ?2, ?3)').bind(crypto.randomUUID(), received, JSON.stringify(report)).run();
      return;
    }
    // The time of receipt also goes into the key's metadata, so the live view can find
    // new reports from a key listing, and into one marker key that dashboards poll.
    await env.REPORTS.put(`csa-2026-01/${received.slice(0, 10)}/${crypto.randomUUID()}`, JSON.stringify({ received, report }), { metadata: { received } });
    try {
      await env.REPORTS.put(LATEST_KEY, received);
    } catch {
      // the report is stored; the live view just notices it later
    }
  },
  // all reports, oldest first, a page at a time
  async page(env, cursor) {
    if (env.DB) {
      const [received = '', id = ''] = (cursor || '').split(' ');
      const { results } = await env.DB.prepare('SELECT id, received, report FROM reports WHERE (received, id) > (?1, ?2) ORDER BY received, id LIMIT ?3').bind(received, id, DB_PAGE).all();
      const last = results[results.length - 1];
      return { items: results.map(row), cursor: results.length === DB_PAGE ? `${last.received} ${last.id}` : '' };
    }
    const page = await env.REPORTS.list({ prefix: 'csa-2026-01/', limit: PAGE, cursor: cursor || undefined });
    return { items: await kvLoad(env, page.keys.map((k) => k.name)), cursor: page.list_complete ? '' : page.cursor };
  },
  // reports received after "since", oldest first, one page
  async since(env, since) {
    if (env.DB) {
      const { results } = await env.DB.prepare('SELECT id, received, report FROM reports WHERE received > ?1 ORDER BY received, id LIMIT ?2').bind(since, DB_PAGE).all();
      return results.map(row);
    }
    // KV keys are grouped by day, so only the days from then until now are listed (three at most)
    const names = [];
    for (let day = Date.parse(since.slice(0, 10)), n = 0; day <= Date.now() && n < 3; day += 86_400_000, n++) {
      let cursor;
      do {
        const page = await env.REPORTS.list({ prefix: `csa-2026-01/${new Date(day).toISOString().slice(0, 10)}/`, cursor });
        for (const k of page.keys) if (k.metadata && k.metadata.received > since) names.push({ name: k.name, received: k.metadata.received });
        cursor = page.list_complete ? undefined : page.cursor;
      } while (cursor);
    }
    names.sort((a, b) => (a.received < b.received ? -1 : 1));
    return kvLoad(env, names.slice(0, PAGE).map((n) => n.name));
  },
  async latest(env) {
    if (env.DB) return (await env.DB.prepare('SELECT max(received) AS latest FROM reports').first('latest')) || '';
    return (await env.REPORTS.get(LATEST_KEY)) || '';
  },
};

async function submit(request, env) {
  const raw = await request.text();
  if (raw.length > MAX_BYTES) return text('too large', 413);
  let report;
  try {
    report = JSON.parse(raw);
  } catch {
    return text('not JSON', 400);
  }
  const problem = validate(report);
  if (problem) return text(problem, 400);
  if ('device_id' in report) report.device_id = await sealDeviceId(env, report.device_id);
  await reports.add(env, new Date().toISOString(), report);
  return text('stored, thank you');
}

const maintainer = (request, env) => Boolean(env.EXPORT_TOKEN) && request.headers.get('authorization') === `Bearer ${env.EXPORT_TOKEN}`;

// For the maintainers: all reports as JSON lines, a page per call. Only with the secret
// EXPORT_TOKEN; without that secret the address does not exist.
async function exportReports(request, env) {
  if (!maintainer(request, env)) return text('not found', 404);
  const page = await reports.page(env, new URL(request.url).searchParams.get('cursor'));
  return new Response(page.items.map((x) => JSON.stringify({ received: x.received, report: x.report })).join('\n') + '\n', {
    headers: { 'content-type': 'application/x-ndjson', 'cache-control': 'no-store', 'x-next-cursor': page.cursor },
  });
}

// One-off move from KV to D1, 40 reports per call, for the maintainers. It copies and
// leaves KV as it is; a report that is already in the table is skipped, so the call can
// be repeated. The answer says how to continue.
async function migrate(request, env) {
  if (!maintainer(request, env)) return text('not found', 404);
  if (!env.DB) return text('no D1 database bound as DB', 400);
  const page = await env.REPORTS.list({ prefix: 'csa-2026-01/', limit: PAGE, cursor: new URL(request.url).searchParams.get('cursor') || undefined });
  const items = await kvLoad(env, page.keys.map((k) => k.name));
  const insert = env.DB.prepare('INSERT OR IGNORE INTO reports (id, received, report) VALUES (?1, ?2, ?3)');
  if (items.length) await env.DB.batch(items.map((x) => insert.bind(x.id, x.received, JSON.stringify(x.report))));
  const total = await env.DB.prepare('SELECT count(*) AS n FROM reports').first('n');
  return new Response(JSON.stringify({ copied: items.length, in_database: total, cursor: page.list_complete ? '' : page.cursor }) + '\n', {
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });
}

// The dashboard is for the team only. Cloudflare Access sits in front of it and signs
// every request it lets through; the worker checks that signature itself, so the page
// stays closed when Access is missing or covers the wrong path. Without ACCESS_TEAM_DOMAIN
// and ACCESS_AUD the dashboard does not exist.
let accessKeys = { at: 0, keys: [] };
const b64 = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));

export async function accessUser(request, env) {
  if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) return null;
  const [head, body, sig] = (request.headers.get('cf-access-jwt-assertion') || '').split('.');
  if (!sig) return null;
  try {
    const header = JSON.parse(new TextDecoder().decode(b64(head)));
    const claims = JSON.parse(new TextDecoder().decode(b64(body)));
    const issuer = `https://${env.ACCESS_TEAM_DOMAIN}`;
    if (header.alg !== 'RS256' || claims.iss !== issuer || !(claims.exp > Date.now() / 1000)) return null;
    if (![].concat(claims.aud).includes(env.ACCESS_AUD)) return null;
    if (Date.now() - accessKeys.at > 600_000 || !accessKeys.keys.some((k) => k.kid === header.kid)) {
      const res = await fetch(`${issuer}/cdn-cgi/access/certs`);
      accessKeys = { at: Date.now(), keys: (await res.json()).keys || [] };
    }
    const jwk = accessKeys.keys.find((k) => k.kid === header.kid);
    if (!jwk) return null;
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64(sig), new TextEncoder().encode(`${head}.${body}`));
    return ok ? claims.email || 'signed in' : null;
  } catch {
    return null;
  }
}

async function dashboard(request, env, data) {
  const user = await accessUser(request, env);
  if (!user) return text('not found', 404);
  if (data === 'labels') {
    const out = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
    if (request.method === 'GET') return out({ labels: await labels.all(env), you: user });
    // a change: only from the dashboard itself. A form on another site cannot send JSON,
    // and the browser names the page a request comes from.
    if (!(request.headers.get('content-type') || '').startsWith('application/json') || request.headers.get('origin') !== new URL(request.url).origin) return text('not from the dashboard', 403);
    let body;
    try { body = JSON.parse((await request.text()).slice(0, 8192)); } catch { return text('not JSON', 400); }
    const bad = validLabel(body);
    if (bad) return text(bad, 400);
    await labels.set(env, body.key, body.verdict ? { verdict: body.verdict, note: body.note, hashes: body.hashes, by: user, at: new Date().toISOString() } : null);
    return out({ labels: await labels.all(env), you: user });
  }
  if (!data) {
    return new Response(DASHBOARD, {
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
        'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
      },
    });
  }
  const json = (body) => new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
  const params = new URL(request.url).searchParams;
  if (data === 'latest') return json({ latest: await reports.latest(env) });
  const since = params.get('since');
  if (since) {
    // live view: only reports received after "since"
    if (!/^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/.test(since)) return text('bad since', 400);
    return json({ items: await reports.since(env, since), cursor: '' });
  }
  return json(await reports.page(env, params.get('cursor')));
}

// The script itself, served from here instead of raw.githubusercontent.com, which keeps
// a file for five minutes after a push. The worker only ever takes the script from the
// main branch of the official repository: it asks GitHub which commit main points to and
// fetches the file by that commit, an address GitHub does not cache. The commit comes from
// the address git itself uses (info/refs); GitHub's API limits anonymous calls per IP
// address, and workers share theirs with many others. Anyone may call
// /refresh; it can only bring the copy here in line with main, at most twice a minute.
const REPO = 'admonstrator/glinet-csa-2026-01';
const SCRIPT = 'gl-helper-triage.sh';
const SCRIPT_KEY = 'script/csa-2026-01-fix';
const RAW_MAIN = `https://raw.githubusercontent.com/${REPO}/main/${SCRIPT}`;

async function refreshScript(env, force) {
  const have = JSON.parse((await env.REPORTS.get(SCRIPT_KEY)) || 'null');
  if (have && !force && Date.now() - have.checked < 600_000) return have;
  if (have && Date.now() - have.checked < 30_000) return have;
  try {
    const refs = await fetch(`https://github.com/${REPO}.git/info/refs?service=git-upload-pack`, { headers: { 'user-agent': 'git/2.43.0' } });
    const commit = ((await refs.text()).match(/([0-9a-f]{40}) refs\/heads\/main\n/) || [])[1];
    if (!refs.ok || !commit) throw new Error('no commit');
    let body = have && have.commit === commit ? have.body : null;
    if (body === null) {
      const raw = await fetch(`https://raw.githubusercontent.com/${REPO}/${commit}/${SCRIPT}`);
      body = await raw.text();
      if (!raw.ok || !body.startsWith('#!/bin/sh') || body.length < 1000 || body.length > 500_000) throw new Error('no script');
    }
    const next = { commit, body, checked: Date.now() };
    await env.REPORTS.put(SCRIPT_KEY, JSON.stringify(next));
    return next;
  } catch {
    // GitHub not reachable or rate limited: keep what we have, try again later
    if (have) await env.REPORTS.put(SCRIPT_KEY, JSON.stringify({ ...have, checked: Date.now() - 570_000 }));
    return have;
  }
}

async function script(request, env, ctx, pathname) {
  if (pathname.endsWith('/refresh')) {
    if (request.method !== 'POST') return text('method not allowed', 405);
    const now = await refreshScript(env, true);
    return now ? text(now.commit) : text('could not reach GitHub', 502);
  }
  if (request.method !== 'GET' && request.method !== 'HEAD') return text('method not allowed', 405);
  let have = JSON.parse((await env.REPORTS.get(SCRIPT_KEY)) || 'null');
  if (!have) have = await refreshScript(env, true);
  else if (Date.now() - have.checked > 600_000) ctx.waitUntil(refreshScript(env, false));
  // nothing stored and GitHub not reachable from here: send the client to GitHub itself
  if (!have) return Response.redirect(RAW_MAIN, 302);
  return new Response(request.method === 'HEAD' ? null : have.body, {
    headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'x-script-commit': have.commit },
  });
}

export default {
  async fetch(request, env, ctx) {
    const { pathname } = new URL(request.url);
    if (/\/csa-2026-01-fix(\/|$)/.test(pathname)) return script(request, env, ctx, pathname);
    if (pathname.endsWith('/migrate')) {
      // a browser, or curl without -X POST, sends GET and would only see the text below
      if (request.method !== 'POST') return text('This address needs POST: curl -X POST -H "Authorization: Bearer <EXPORT_TOKEN>" <this address>', 405);
      return migrate(request, env);
    }
    if (pathname.endsWith('/dashboard/labels') && (request.method === 'GET' || request.method === 'POST')) return dashboard(request, env, 'labels');
    if (request.method === 'POST') return submit(request, env);
    if (request.method === 'GET' && pathname.endsWith('/export')) return exportReports(request, env);
    if (request.method === 'GET' && /\/dashboard\/?$/.test(pathname)) return dashboard(request, env, false);
    if (request.method === 'GET' && pathname.endsWith('/dashboard/data')) return dashboard(request, env, true);
    if (request.method === 'GET' && pathname.endsWith('/dashboard/latest')) return dashboard(request, env, 'latest');
    if (request.method === 'GET') {
      return text(
        'This address receives the short, anonymous reports of the community script for CSA-2026-01.\n' +
          'The script sends one only when its user agrees. Details: https://gl-i.net/security/csa-2026-01/fix/',
      );
    }
    return text('method not allowed', 405);
  },
};
