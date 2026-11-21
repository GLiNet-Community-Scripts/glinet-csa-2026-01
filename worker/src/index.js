// Collects the short, anonymous reports that gl-helper-triage.sh sends when its user
// agrees. One report is a few facts about a device (model, firmware, which indicators
// were found, when). The worker stores exactly the fields listed below and nothing
// about the sender: no IP address, no country, no headers.

const MAX_BYTES = 8192;
const SAFE = /^[A-Za-z0-9 ._:\/+@=,()-]*$/;
const TIME = /^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC)?$/;

const str = (max) => (v) => typeof v === 'string' && v.length <= max && SAFE.test(v);
const int = (v) => Number.isInteger(v) && v >= 0 && v <= 1e9;
const time = (v) => typeof v === 'string' && TIME.test(v);
const list = (max, item) => (v) => Array.isArray(v) && v.length <= max && v.every(item);

// Every field is required; anything else in a report is refused.
const FIELDS = {
  schema: (v) => v === 1 || v === 2,
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
const isFile = (v) =>
  v !== null && typeof v === 'object' && !Array.isArray(v) &&
  Object.keys(v).length === Object.keys(FILE).length && Object.entries(FILE).every(([k, ok]) => ok(v[k]));
const FIELDS_V2 = { ...FIELDS, state_file_time: time, files: list(12, isFile) };

const text = (body, status = 200) =>
  new Response(body + '\n', { status, headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' } });

export function validate(report) {
  if (report === null || typeof report !== 'object' || Array.isArray(report)) return 'not an object';
  const fields = report.schema === 2 ? FIELDS_V2 : FIELDS;
  for (const key of Object.keys(report)) if (!(key in fields)) return `unknown field ${key.slice(0, 32)}`;
  for (const [key, ok] of Object.entries(fields)) if (!ok(report[key])) return `bad or missing field ${key}`;
  return null;
}

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
  const received = new Date().toISOString();
  await env.REPORTS.put(`csa-2026-01/${received.slice(0, 10)}/${crypto.randomUUID()}`, JSON.stringify({ received, report }));
  return text('stored, thank you');
}

// For the maintainers: all reports as JSON lines, 100 per call. Only with the secret
// EXPORT_TOKEN; without that secret the address does not exist.
async function exportReports(request, env) {
  if (!env.EXPORT_TOKEN || request.headers.get('authorization') !== `Bearer ${env.EXPORT_TOKEN}`) return text('not found', 404);
  const cursor = new URL(request.url).searchParams.get('cursor') || undefined;
  const page = await env.REPORTS.list({ prefix: 'csa-2026-01/', limit: 100, cursor });
  const lines = await Promise.all(page.keys.map((k) => env.REPORTS.get(k.name)));
  return new Response(lines.filter(Boolean).join('\n') + '\n', {
    headers: { 'content-type': 'application/x-ndjson', 'cache-control': 'no-store', 'x-next-cursor': page.list_complete ? '' : page.cursor },
  });
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    if (request.method === 'POST') return submit(request, env);
    if (request.method === 'GET' && pathname.endsWith('/export')) return exportReports(request, env);
    if (request.method === 'GET') {
      return text(
        'This address receives the short, anonymous reports of the community script for CSA-2026-01.\n' +
          'The script sends one only when its user agrees. Details: https://gl-i.net/security/csa-2026-01/fix/',
      );
    }
    return text('method not allowed', 405);
  },
};
