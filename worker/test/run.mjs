// node worker/test/run.mjs          run the tests
// node worker/test/run.mjs serve    serve the worker on 127.0.0.1:8787 with a KV in memory
import worker, { validate } from '../src/index.js';
import http from 'node:http';

const store = new Map();
const env = {
  EXPORT_TOKEN: 'test-token',
  REPORTS: {
    put: async (k, v) => void store.set(k, v),
    get: async (k) => store.get(k) ?? null,
    list: async ({ prefix }) => ({ keys: [...store.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name })), list_complete: true }),
  },
};
const good = {
  schema: 1, tool: '2.1', platform: 'openwrt', model: 'GL-AXT1800', firmware: '4.8.3',
  checked_at: '2026-11-21 16:40:00 UTC', uptime_s: 86400, ioc: 3, persist: 0, review: 2,
  findings: ['process', 'pipe /tmp/f', 'connection 170.39.226.0/24'], quick_check: false,
  shell_started: '2026-11-20 21:40:24 UTC', shell_ports: [42499], pipe_time: '',
};
const call = (method, body, headers = {}, path = '/') =>
  worker.fetch(new Request(`https://example.org${path}`, { method, body, headers }), env);

if (process.argv[2] === 'serve') {
  http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const r = await call(req.method, req.method === 'POST' ? Buffer.concat(chunks) : undefined, req.headers, req.url);
    res.writeHead(r.status, Object.fromEntries(r.headers));
    res.end(await r.text());
    if (req.method === 'POST') console.log(r.status, [...store.values()].at(-1) ?? '');
  }).listen(8787, '127.0.0.1');
} else {
  let failed = 0;
  const expect = (name, ok) => { console.log(`${ok ? 'PASS' : 'FAIL'}: ${name}`); if (!ok) failed++; };
  expect('a complete report is valid', validate(good) === null);
  expect('stores a good report', (await call('POST', JSON.stringify(good), { 'cf-connecting-ip': '203.0.113.9' })).status === 200 && store.size === 1);
  expect('stored value has only the report and a time', (() => { const v = JSON.parse([...store.values()][0]); return Object.keys(v).join() === 'received,report' && !JSON.stringify(v).includes('203.0.113.9'); })());
  expect('refuses an unknown field', (await call('POST', JSON.stringify({ ...good, hostname: 'x' }))).status === 400);
  expect('refuses a missing field', (await call('POST', JSON.stringify({ ...good, model: undefined }))).status === 400);
  expect('refuses odd characters', (await call('POST', JSON.stringify({ ...good, model: '<script>' }))).status === 400);
  expect('refuses a long list', (await call('POST', JSON.stringify({ ...good, findings: Array(41).fill('x') }))).status === 400);
  expect('refuses a large body', (await call('POST', 'x'.repeat(5000))).status === 413);
  expect('refuses text that is not JSON', (await call('POST', 'hello')).status === 400);
  expect('nothing but the good report was stored', store.size === 1);
  expect('export needs the token', (await call('GET', undefined, {}, '/export')).status === 404);
  const exp = await call('GET', undefined, { authorization: 'Bearer test-token' }, '/export');
  expect('export returns the report', exp.status === 200 && (await exp.text()).includes('GL-AXT1800'));
  expect('GET explains the address', (await (await call('GET')).text()).includes('anonymous reports'));
  console.log(failed ? `${failed} failed` : 'all passed');
  process.exit(failed ? 1 : 0);
}
