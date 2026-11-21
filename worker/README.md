# Report worker

A Cloudflare Worker that receives the short, anonymous reports `gl-helper-triage.sh`
sends when its user agrees, and stores them in a KV namespace.

It stores the fields listed in `src/index.js` and the time of receipt. It does not store
the sender's IP address, country or any header, and its logs are switched off. Cloudflare
itself still sees the connection, as with every website behind it.

## Set up

Needs a Cloudflare account and Node.js. All commands run in this folder.

```bash
npx wrangler login
```

```bash
npx wrangler kv namespace create REPORTS
```

Copy the `id` it prints into `wrangler.toml` (replace `REPLACE_WITH_KV_NAMESPACE_ID`).
Older wrangler versions spell the command `kv:namespace create`.

```bash
npx wrangler deploy
```

This prints the worker's address, `https://csa-2026-01-report.<your-subdomain>.workers.dev`.

```bash
npx wrangler secret put EXPORT_TOKEN
```

Enter a long random value. It protects the export; without it the export does not exist.

## Give it its address

The script sends to `https://app.gl-i.net/csa-2026-01-report`. A redirect to the
`workers.dev` address does not work: `curl` and `wget` turn a redirected POST into a GET.
The worker has to answer on that address itself. With `gl-i.net` as a zone in the same
Cloudflare account and `app.gl-i.net` proxied (orange cloud), add this to `wrangler.toml`
and deploy again:

```toml
routes = [{ pattern = "app.gl-i.net/csa-2026-01-report*", zone_name = "gl-i.net" }]
```

If `app.gl-i.net` is not behind Cloudflare, use the `workers.dev` address and change
`REPORT_URL` in `gl-helper-triage.sh`.

## Check it

```bash
curl https://app.gl-i.net/csa-2026-01-report
```

```bash
curl -H "Authorization: Bearer <EXPORT_TOKEN>" https://app.gl-i.net/csa-2026-01-report/export
```

The export returns up to 100 reports as JSON lines. When there are more, the response
header `x-next-cursor` has the value for `?cursor=`.

To test a full round, run the script on a device with `--report`. It sends a report even
when nothing was found.

## Protect it

Anyone can send made-up reports; the worker only checks their shape and size (4 KB). In
the Cloudflare dashboard, add a rate limiting rule for the path
`/csa-2026-01-report`, for example 10 requests per minute per IP address.

## Tests

```bash
node test/run.mjs
```

```bash
node test/run.mjs serve
```

The second command serves the worker on `127.0.0.1:8787` with storage in memory. Point the
script at it with `GL_TRIAGE_REPORT_URL=http://127.0.0.1:8787/`.
