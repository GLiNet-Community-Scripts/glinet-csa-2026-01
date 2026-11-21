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

## Serving the script

The worker also serves the script itself at `https://app.gl-i.net/csa-2026-01-fix`, so a
change is available at once. (A redirect to `raw.githubusercontent.com` shows the old
file for up to five minutes after a push.)

The worker takes the script only from the `main` branch of this repository. It asks
GitHub which commit `main` points to (the way `git` does, not through the API with its
limit on anonymous calls), fetches `gl-helper-triage.sh` by that commit and
keeps it in KV. The response header `x-script-commit` says which commit is served.

- `.github/workflows/publish-script.yml` calls `POST /csa-2026-01-fix/refresh` after every
  push that changes the script. The call needs no secret: it can only bring the copy in
  line with `main`, and the worker answers it at most every 30 seconds.
- Without that call the worker checks by itself when its copy is older than 10 minutes.
- If GitHub cannot be reached, the stored copy keeps being served.

To switch over, add a second route in `wrangler.toml` and deploy:

```toml
routes = [
  { pattern = "app.gl-i.net/csa-2026-01-report*", zone_name = "gl-i.net" },
  { pattern = "app.gl-i.net/csa-2026-01-fix*", zone_name = "gl-i.net" },
]
```

Then remove the redirect rule that sends `/csa-2026-01-fix` to GitHub. As long as it
exists, Cloudflare answers with the redirect and the worker is never asked.

```bash
curl -sI https://app.gl-i.net/csa-2026-01-fix
```

shows `x-script-commit` when the worker answers, and `location:` when the redirect is
still in place.

## Dashboard for the team

`https://app.gl-i.net/csa-2026-01-report/dashboard` shows what the reports add up to:
how many devices have traces and of which kind, when it started, which models and
firmware builds, the malware's files by fingerprint, and the commands, autostart lines
and firewall rules the attacker left, with identical ones grouped. Below that is a
sortable, paged table of the reports; a row opens to its details.

Everything can be filtered: by device, firmware and kind of evidence (lists with counts),
by result, device type, time received and whether the device was restarted since the
attack, and by free text. Bars and chart columns set a filter when clicked. "Export CSV"
downloads the reports that match. All times are UTC, to the minute.

The page loads all reports into the browser, 100 per request. That is fine for a few
thousand; beyond that the worker should pre-aggregate.

The page is `src/dashboard.html`. The worker imports `src/dashboard.js`, which
`node build.mjs` generates from it; run that after every change to the page.
It is for the team only. Cloudflare Access sits in front of it, and the worker checks the
signature Access adds to every request. Until both settings below are present, the
dashboard answers "not found" for everyone.

1. In the Cloudflare dashboard open **Zero Trust → Access → Applications** and add a
   **self-hosted** application:
   - domain `app.gl-i.net`, path `csa-2026-01-report/dashboard`
   - a policy with action **Allow** that lists the e-mail addresses of the team

   Only this path. The address the script posts to must stay open, or routers cannot
   send reports.
2. Note two values: the **Application Audience (AUD) tag** of the application, and your
   **team domain** (Zero Trust → Settings, it looks like `yourteam.cloudflareaccess.com`).
3. Add them to `wrangler.toml`, above the first `[section]`, and deploy:

   ```toml
   [vars]
   ACCESS_TEAM_DOMAIN = "yourteam.cloudflareaccess.com"
   ACCESS_AUD = "the AUD tag"
   ```

   A `[vars]` block is a section of its own: put it after `routes = ...` and before or
   after the other sections, not inside `[[kv_namespaces]]`.

   ```bash
   npx wrangler deploy
   ```

Team members open the address, sign in with the one-time code Access mails them, and see
the table. The names of the menus in the Cloudflare dashboard change now and then.

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
