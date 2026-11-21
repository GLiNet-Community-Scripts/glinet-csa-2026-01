// node worker/test/run.mjs          run the tests
// node worker/test/run.mjs serve    serve the worker on 127.0.0.1:8787 with a KV in memory
import worker, { validate } from '../src/index.js';
import http from 'node:http';

import { readFileSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
const store = new Map(), meta = new Map();
// D1 as the worker sees it, backed by a real SQLite database with the real schema
function d1() {
  const db = new DatabaseSync(':memory:'); db.exec(readFileSync(new URL('../schema.sql', import.meta.url), 'utf8'));
  const stmt = (sql, args = []) => ({
    bind: (...a) => stmt(sql, a),
    run: async () => void db.prepare(sql).run(...args),
    all: async () => ({ results: db.prepare(sql).all(...args) }),
    first: async (col) => { const r = db.prepare(sql).get(...args); return r ? (col ? r[col] : r) : null; },
  });
  return { prepare: (sql) => stmt(sql), batch: async (list) => { for (const s of list) await s.run(); }, raw: db };
}
const env = {
  EXPORT_TOKEN: 'test-token',
  REPORTS: {
    put: async (k, v, o) => { store.set(k, v); if (o && o.metadata) meta.set(k, o.metadata); },
    get: async (k) => store.get(k) ?? null,
    list: async ({ prefix }) => ({ keys: [...store.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name, metadata: meta.get(name) })), list_complete: true }),
  },
};
const good = {
  schema: 1, tool: '2.1', platform: 'openwrt', model: 'GL-AXT1800', firmware: '4.8.3',
  checked_at: '2026-11-21 16:40:00 UTC', uptime_s: 86400, ioc: 3, persist: 0, review: 2,
  findings: ['process', 'pipe /tmp/f', 'connection 170.39.226.0/24'], quick_check: false,
  shell_started: '2026-11-20 21:40:24 UTC', shell_ports: [42499], pipe_time: '',
};
const file = { path: '/etc/config/.gl/gl-helper', sha256: 'a'.repeat(64), size: 123456, mtime: '2026-11-20 21:40:30 UTC' };
const good2 = { ...good, schema: 2, tool: '2.2', state_file_time: '2026-11-20 22:15:18 UTC', files: [file] };
const good3 = {
  ...good2, schema: 3, tool: '2.3',
  persistence: [{ path: '/etc/rc.local', lines: ['/etc/config/.gl/gl-helper -d >/dev/null 2>&1 &'] }],
  fw_rules: ['nat: -A SDWAN_IP_MAPPING -d 127.0.0.1/32 -j DNAT --to-destination 127.0.0.1'],
  commands: ['sh -c iptables -t nat -A SDWAN_IP_MAPPING -d 127.0.0.1 -j DNAT --to-destination 127.0.0.1;(while true;do rm -f /tmp/f;done) "x" \\ &'],
};
const call = (method, body, headers = {}, path = '/csa-2026-01-report') =>
  worker.fetch(new Request(`https://example.org${path}`, { method, body, headers }), env, { waitUntil() {} });

if (process.argv[2] === 'serve') {
  http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const r = await call(req.method, req.method === 'POST' ? Buffer.concat(chunks) : undefined, req.headers, req.url);
    res.writeHead(r.status, Object.fromEntries(r.headers));
    res.end(await r.text());
    if (req.method === 'POST') console.log(r.status, [...store.entries()].filter(([k]) => k.startsWith('csa-2026-01/')).at(-1)?.[1] ?? '');
  }).listen(8787, '127.0.0.1');
} else {
  let failed = 0;
  const expect = (name, ok) => { console.log(`${ok ? 'PASS' : 'FAIL'}: ${name}`); if (!ok) failed++; };
  expect('a complete report is valid', validate(good) === null);
  expect('stores a good report', (await call('POST', JSON.stringify(good), { 'cf-connecting-ip': '203.0.113.9' })).status === 200 && store.size === 2);
  expect('stored value has only the report and a time', (() => { const v = JSON.parse([...store.values()][0]); return Object.keys(v).join() === 'received,report' && !JSON.stringify(v).includes('203.0.113.9'); })());
  expect('refuses an unknown field', (await call('POST', JSON.stringify({ ...good, hostname: 'x' }))).status === 400);
  expect('refuses a missing field', (await call('POST', JSON.stringify({ ...good, model: undefined }))).status === 400);
  expect('refuses odd characters', (await call('POST', JSON.stringify({ ...good, model: '<script>' }))).status === 400);
  expect('refuses a long list', (await call('POST', JSON.stringify({ ...good, findings: Array(41).fill('x') }))).status === 400);
  expect('refuses a large body', (await call('POST', 'x'.repeat(25000))).status === 413);
  expect('a schema 3 report is valid', validate(good3) === null && validate({ ...good3, persistence: [], fw_rules: [], commands: [] }) === null);
  expect('schema 2 must not carry schema 3 fields', validate({ ...good2, commands: [] }) !== null);
  expect('refuses control characters in free text', validate({ ...good3, commands: ['a\u0007b'] }) !== null && validate({ ...good3, fw_rules: ['a\nb'] }) !== null);
  expect('refuses non-ASCII in free text', validate({ ...good3, commands: ['caf\u00e9'] }) !== null);
  expect('refuses long lines and long lists', validate({ ...good3, fw_rules: ['x'.repeat(301)] }) !== null && validate({ ...good3, persistence: [{ path: '/x', lines: Array(21).fill('a') }] }) !== null);
  expect('refuses an extra field in a persistence entry', validate({ ...good3, persistence: [{ path: '/x', lines: [], mode: 1 }] }) !== null);
  expect('a schema 2 report is valid', validate(good2) === null && validate({ ...good2, files: [] }) === null);
  expect('schema 1 must not carry schema 2 fields', validate({ ...good, files: [] }) !== null);
  expect('schema 2 needs its fields', validate({ ...good, schema: 2 }) !== null);
  expect('refuses a bad hash', validate({ ...good2, files: [{ ...file, sha256: 'xyz' }] }) !== null);
  expect('refuses an extra field in a file', validate({ ...good2, files: [{ ...file, content: 'x' }] }) !== null);
  expect('refuses more than 12 files', validate({ ...good2, files: Array(13).fill(file) }) !== null);
  expect('refuses text that is not JSON', (await call('POST', 'hello')).status === 400);
  expect('nothing but the good report and the marker was stored', store.size === 2 && store.has('meta/csa-2026-01-latest'));
  expect('export needs the token', (await call('GET', undefined, {}, '/csa-2026-01-report/export')).status === 404);
  const exp = await call('GET', undefined, { authorization: 'Bearer test-token' }, '/csa-2026-01-report/export');
  expect('export returns the report', exp.status === 200 && (await exp.text()).includes('GL-AXT1800'));
  expect('GET explains the address', (await (await call('GET')).text()).includes('anonymous reports'));

  // dashboard: only with a valid Cloudflare Access token
  const { publicKey, privateKey } = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  const jwk = { ...(await crypto.subtle.exportKey('jwk', publicKey)), kid: 'k1' };
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (u) => new Response(JSON.stringify({ keys: String(u).startsWith('https://team.cloudflareaccess.com/') ? [jwk] : [] }));
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const token = async (claims, key = privateKey) => {
    const data = `${enc({ alg: 'RS256', kid: 'k1' })}.${enc(claims)}`;
    return `${data}.${Buffer.from(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, Buffer.from(data))).toString('base64url')}`;
  };
  const claims = { iss: 'https://team.cloudflareaccess.com', aud: ['aud-1'], exp: Date.now() / 1000 + 600, email: 'a@example.org' };
  const dash = (jwt, path = '/csa-2026-01-report/dashboard') => call('GET', undefined, jwt ? { 'cf-access-jwt-assertion': jwt } : {}, path);
  expect('dashboard does not exist while Access is not configured', (await dash(await token(claims))).status === 404);
  env.ACCESS_TEAM_DOMAIN = 'team.cloudflareaccess.com'; env.ACCESS_AUD = 'aud-1';
  expect('dashboard without a token: not found', (await dash()).status === 404);
  expect('dashboard with a valid token', (await dash(await token(claims))).status === 200);
  expect('wrong audience is refused', (await dash(await token({ ...claims, aud: ['other'] }))).status === 404);
  expect('expired token is refused', (await dash(await token({ ...claims, exp: Date.now() / 1000 - 5 }))).status === 404);
  expect('wrong issuer is refused', (await dash(await token({ ...claims, iss: 'https://evil.example' }))).status === 404);
  const other = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  expect('token signed with another key is refused', (await dash(await token(claims, other.privateKey))).status === 404);
  const forged = (await token(claims)).split('.'); forged[0] = enc({ alg: 'none', kid: 'k1' });
  expect('alg none is refused', (await dash(forged.join('.'))).status === 404);
  const data = await dash(await token(claims), '/csa-2026-01-report/dashboard/data');
  expect('data needs the token too', (await dash(undefined, '/csa-2026-01-report/dashboard/data')).status === 404);
  const first = (await data.json()).items[0];
  expect('data returns the reports, each with an id', data.status === 200 && first.report.model === 'GL-AXT1800' && first.id.startsWith('csa-2026-01/'));
  // live view
  const tok = await token(claims), live = (path) => dash(tok, '/csa-2026-01-report/dashboard/' + path);
  expect('latest needs the token', (await dash(undefined, '/csa-2026-01-report/dashboard/latest')).status === 404);
  const mark = (await (await live('latest')).json()).latest;
  expect('latest gives the time of the newest report', mark === first.received);
  expect('nothing is newer than the newest', (await (await live('data?since=' + mark)).json()).items.length === 0);
  await new Promise((r) => setTimeout(r, 5));
  await call('POST', JSON.stringify({ ...good, model: 'GL-MT6000' }));
  const fresh = (await (await live('data?since=' + mark)).json()).items;
  expect('a new report shows up after "since", and only that one', fresh.length === 1 && fresh[0].report.model === 'GL-MT6000');
  expect('latest moves on', (await (await live('latest')).json()).latest === fresh[0].received);
  expect('a bad since is refused', (await live('data?since=yesterday')).status === 400);
  globalThis.fetch = realFetch;

  // the script, served from the worker
  const SH = (n) => '#!/bin/sh\n# version ' + n + '\n' + 'x'.repeat(1200);
  const gh = { commit: 'a'.repeat(40), calls: 0, down: false };
  const before = globalThis.fetch;
  globalThis.fetch = async (u) => {
    gh.calls++;
    if (gh.down) return new Response('rate limited', { status: 403 });
    if (String(u) === 'https://github.com/admonstrator/glinet-csa-2026-01.git/info/refs?service=git-upload-pack')
      return new Response(`001e# service=git-upload-pack\n0000015a${'f'.repeat(40)} HEAD\0multi_ack symref=HEAD:refs/heads/main\n003d${'e'.repeat(40)} refs/heads/feature\n003f${gh.commit} refs/heads/main\n0000`);
    if (String(u) === `https://raw.githubusercontent.com/admonstrator/glinet-csa-2026-01/${gh.commit}/gl-helper-triage.sh`) return new Response(SH(gh.commit[0]));
    return new Response('not found', { status: 404 });
  };
  const waits = [];
  const ctx = { waitUntil: (p) => waits.push(p) };
  const fix = (method = 'GET', path = '/csa-2026-01-fix') => worker.fetch(new Request(`https://example.org${path}`, { method }), env, ctx);
  const age = (ms) => { const v = JSON.parse(store.get('script/csa-2026-01-fix')); v.checked -= ms; store.set('script/csa-2026-01-fix', JSON.stringify(v)); };
  let r = await fix();
  expect('first download fetches the script from main', r.status === 200 && (await r.text()).startsWith('#!/bin/sh\n# version a') && r.headers.get('x-script-commit') === gh.commit);
  expect('it is not cached by clients', r.headers.get('cache-control') === 'no-store');
  const calls = gh.calls; await fix();
  expect('later downloads come from the store, no call to GitHub', gh.calls === calls);
  gh.commit = 'b'.repeat(40);
  r = await fix('POST', '/csa-2026-01-fix/refresh');
  expect('refresh within 30 seconds does nothing', (await r.text()).trim() === 'a'.repeat(40));
  age(31_000); r = await fix('POST', '/csa-2026-01-fix/refresh');
  expect('refresh picks up the new commit', r.status === 200 && (await r.text()).trim() === gh.commit && (await (await fix()).text()).includes('# version b'));
  gh.commit = 'c'.repeat(40); age(601_000); r = await fix(); await Promise.all(waits);
  expect('an old copy is served at once and renewed in the background', (await r.text()).includes('# version b') && (await (await fix()).text()).includes('# version c'));
  gh.down = true; age(601_000); r = await fix(); await Promise.all(waits);
  expect('GitHub down: the stored copy keeps being served', r.status === 200 && (await r.text()).includes('# version c') && (await fix()).status === 200);
  store.delete('script/csa-2026-01-fix'); r = await fix();
  expect('nothing stored and GitHub down: redirect to GitHub', r.status === 302 && r.headers.get('location').includes('raw.githubusercontent.com'));
  gh.down = false;
  expect('a report cannot be posted to the script address', (await worker.fetch(new Request('https://example.org/csa-2026-01-fix', { method: 'POST', body: JSON.stringify(good) }), env, ctx)).status === 405);
  expect('the stored script is not listed as a report', !(await (await call('GET', undefined, { authorization: 'Bearer test-token' }, '/csa-2026-01-report/export')).text()).includes('#!/bin/sh'));
  expect('reports still work', (await call('POST', JSON.stringify(good))).status === 200);
  globalThis.fetch = before;

  // device id (schema 4)
  const good4 = { ...good3, schema: 4, tool: '2.9', device_id: '0123456789abcdef' };
  const lastReport = () => JSON.parse([...store.entries()].filter(([k]) => k.startsWith('csa-2026-01/')).at(-1)[1]).report;
  expect('a schema 4 report is valid, with or without an id', validate(good4) === null && validate({ ...good4, device_id: '' }) === null);
  expect('refuses a device id that is not 16 hex characters', validate({ ...good4, device_id: 'aa:bb:cc:dd:ee:ff' }) !== null && validate({ ...good4, device_id: '0123456789ABCDEF' }) !== null);
  expect('schema 3 must not carry a device id', validate({ ...good3, device_id: '' }) !== null);
  await call('POST', JSON.stringify(good4));
  expect('without the secret the id is dropped', lastReport().device_id === '');
  env.DEVICE_SALT = 'test-salt';
  await call('POST', JSON.stringify(good4)); const sealed = lastReport().device_id;
  expect('with the secret a short sealed id is stored, not what was sent', /^[0-9a-f]{12}$/.test(sealed) && !'0123456789abcdef'.includes(sealed) && !JSON.stringify(lastReport()).includes('0123456789abcdef'));
  await call('POST', JSON.stringify({ ...good4, model: 'again' }));
  expect('the same device gets the same id', lastReport().device_id === sealed);
  await call('POST', JSON.stringify({ ...good4, device_id: 'fedcba9876543210' }));
  expect('another device gets another id', lastReport().device_id !== sealed && lastReport().device_id.length === 12);
  env.DEVICE_SALT = 'other-salt'; await call('POST', JSON.stringify(good4));
  expect('another secret gives another id', lastReport().device_id !== sealed); env.DEVICE_SALT = 'test-salt';

  // ---- the same worker on D1
  const kvReports = [...store.keys()].filter((k) => k.startsWith('csa-2026-01/')).length;
  const auth = { authorization: 'Bearer test-token' }, mig = (q = '') => call('POST', undefined, auth, '/csa-2026-01-report/migrate' + q);
  expect('migrate refuses without a database', (await mig()).status === 400);
  expect('migrate by GET says to use POST', (await call('GET', undefined, auth, '/csa-2026-01-report/migrate')).status === 405);
  env.DB = d1();
  expect('migrate needs the token', (await call('POST', undefined, {}, '/csa-2026-01-report/migrate')).status === 404);
  const m1 = await (await mig()).json();
  expect('migrate copies the KV reports', m1.copied === kvReports && m1.in_database === kvReports && m1.cursor === '');
  const m2 = await (await mig()).json();
  expect('migrate can be repeated without duplicates', m2.in_database === kvReports);
  expect('KV is left as it was', [...store.keys()].filter((k) => k.startsWith('csa-2026-01/')).length === kvReports);
  const dtok = await (async () => { globalThis.fetch = async () => new Response(JSON.stringify({ keys: [jwk] })); return token(claims); })();
  const d = (path) => call('GET', undefined, { 'cf-access-jwt-assertion': dtok }, '/csa-2026-01-report/dashboard/' + path);
  const all1 = (await (await d('data')).json());
  expect('dashboard reads the moved reports from D1', all1.items.length === kvReports && all1.cursor === '' && all1.items[0].report.model === 'GL-AXT1800');
  const writesBefore = store.size;
  expect('a new report goes to D1', (await call('POST', JSON.stringify({ ...good3, model: 'GL-D1' }))).status === 200 && store.size === writesBefore);
  const latest1 = (await (await d('latest')).json()).latest, newer = (await (await d('data?since=' + all1.items.at(-1).received)).json()).items;
  expect('latest and since work on D1', newer.length === 1 && newer[0].report.model === 'GL-D1' && newer[0].received === latest1 && newer[0].report.persistence.length === 1);
  expect('nothing newer than the newest on D1', (await (await d('data?since=' + latest1)).json()).items.length === 0);
  const ins = env.DB.raw.prepare('INSERT INTO reports (id, received, report) VALUES (?, ?, ?)');
  for (let i = 0; i < 1100; i++) ins.run('bulk' + String(i).padStart(5, '0'), '2026-11-22T10:00:00.' + String(i % 1000).padStart(3, '0') + 'Z', JSON.stringify(good));
  let cur = '', got = 0, pages = 0; const ids = new Set();
  do { const pg = await (await d('data' + (cur ? '?cursor=' + encodeURIComponent(cur) : ''))).json(); pg.items.forEach((x) => ids.add(x.id)); got += pg.items.length; cur = pg.cursor; pages++; } while (cur && pages < 10);
  expect('paging on D1 returns every report once, also with equal times', got === kvReports + 1 + 1100 && ids.size === got && pages === 3);
  const ex = await call('GET', undefined, auth, '/csa-2026-01-report/export');
  expect('export works on D1', ex.status === 200 && (await ex.text()).split('\n').filter(Boolean).length === 500 && ex.headers.get('x-next-cursor') !== '');
  expect('a bad report is still refused on D1', (await call('POST', JSON.stringify({ ...good, hostname: 'x' }))).status === 400);
  globalThis.fetch = realFetch;
  console.log(failed ? `${failed} failed` : 'all passed');
  process.exit(failed ? 1 : 0);
}
