# Report worker

A Cloudflare Worker that receives the short, anonymous reports `gl-helper-triage.sh`
sends when its user agrees, and stores them in a KV namespace.

It stores the fields listed in `src/index.js` and the time of receipt. It does not store
the sender's IP address, country or any header, and its logs are switched off. Cloudflare
itself still sees the connection, as with every website behind it.

## Set up

Needs a Cloudflare account and Node.js. All commands run in this folder.

```bash
cp wrangler.example.toml wrangler.toml
```

`wrangler.toml` holds your own settings and is not in git, so `git pull` never collides
with it. To update the worker later: `git pull`, then `npx wrangler deploy`.

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

With `?all=1` the export returns every report in one answer (from D1). Without it, the
export returns a page of reports as JSON lines (500 from D1, 40 from KV). When there are more, the response
header `x-next-cursor` has the value for `?cursor=`.

To test a full round, run the script on a device with `--report`. It sends a report even
when nothing was found.

## Moving the reports to D1

KV on the free plan allows 1,000 writes and listings a day, which is a few hundred
reports. D1, Cloudflare's database, allows 100,000 written rows a day, and the dashboard
gets all reports with a few queries instead of one read per report. The worker uses D1
as soon as a database is bound as `DB`, and KV until then. The KV namespace stays: the
script download keeps its copy there.

1. Create the database. The command prints a `database_id`.

   ```bash
   npx wrangler d1 create csa-2026-01
   ```

2. Create the table.

   ```bash
   npx wrangler d1 execute csa-2026-01 --remote --file=schema.sql
   ```

3. Add the database to `wrangler.toml`, as a section of its own at the end, and deploy.

   ```toml
   [[d1_databases]]
   binding = "DB"
   database_name = "csa-2026-01"
   database_id = "the id from step 1"
   ```

   ```bash
   npx wrangler deploy
   ```

   From now on new reports go to D1. The dashboard shows only those until step 4 is done.

4. Copy the reports that are in KV. Each call copies 40 and says how to go on; repeat it
   with the `cursor` it returns until `cursor` is empty. Calling it again does no harm:
   a report that is already in the table is skipped. KV is not changed.

   ```bash
   curl -X POST -H "Authorization: Bearer <EXPORT_TOKEN>" "https://app.gl-i.net/csa-2026-01-report/migrate"
   ```

   ```bash
   curl -X POST -H "Authorization: Bearer <EXPORT_TOKEN>" "https://app.gl-i.net/csa-2026-01-report/migrate?cursor=<cursor from the answer>"
   ```

   The answer looks like `{"copied":40,"in_database":40,"cursor":"..."}`.

5. Check: the dashboard shows the same number of reports as before, and

   ```bash
   npx wrangler d1 execute csa-2026-01 --remote --command "SELECT count(*) FROM reports"
   ```

   gives the same number.

To go back, remove the `[[d1_databases]]` block and deploy: the worker uses KV again.
Reports that arrived in D1 in the meantime are then not shown.

## Marking findings as probably safe

The dashboard lists what the scripts sent for review. Everyone who may open the dashboard
may mark such a finding as probably safe, with a short note, in the block "Unusual
changes seen on several devices" or inside a single report. A marked finding is hidden
for everyone unless they ask to see it. Each mark records who set it (the address
Cloudflare Access signed in) and when.

A mark belongs to a kind and a path and remembers the fingerprints known for that path at
the time. A file with another fingerprint at the same path brings the finding back, as "new
file at a path marked safe": a replaced file is exactly what should not stay hidden.

Every finding has a page of its own, reached by a click on it: the devices that sent it,
the fingerprints behind its path with the number of devices for each, the models and
firmware, and when the entry changed on the devices. That is the page to look at before
marking something.

The dashboard has a page "Probably safe" that lists every mark with its comment, who set
it and when, and from which a mark can be removed.

The marks are kept in the D1 table `labels`, which the worker creates on first use, or in
one KV entry when there is no database. They can be read at `<worker>/dashboard/labels`
with the dashboard's login. Over time they form a list of what is known to be harmless,
which the script could one day ask for; nothing does that yet.

## Telling devices apart

From script 2.9 a report carries a device id, so that ten reports from one device are not
read as ten devices. The script sends a hash of a hardware address. Such a hash can be
reversed by trying all addresses of a manufacturer, so the worker does not store it: it
stores an HMAC of it with a secret, shortened to 12 characters. Set the secret once:

```bash
npx wrangler secret put DEVICE_SALT
```

Enter a long random value and keep it: with a new value the same device gets a new id,
and reports before and after no longer match. Without the secret the worker drops the id
and every report counts on its own, as before.

In the dashboard "One row per device" folds repeated reports into one. The report with
the most known traces stands for the device, so a device that was hit and later cleaned
still counts as hit.

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

Beyond the counts it shows how an attack ran (the middle value of each time in the
reports, with how long the attacker was active and how long it took to find), the ports
of the remote shells and whether they were handed out in order, and a grid of models by
firmware versions with the share of devices that had traces. "Copy as advisory YAML"
turns that grid into the `reported` block of the advisory on gl-i.net. A report that
carries something no other device has (a file fingerprint, a command, an autostart line)
is marked "Unusual". Firmware is shown as the version, with beta or rc where there is
one; the build number and date are in each report.

The filters are kept in the address, so a link shows someone else the same view, and the
page offers the reports that are new since your last visit.

Everything can be filtered: by device, firmware and kind of evidence (lists with counts),
by result, device type, time received and whether the device was restarted since the
attack, and by free text. Bars and chart columns set a filter when clicked. "Export CSV"
downloads the reports that match. All times are UTC, to the minute.

The page keeps itself up to date: every 20 seconds it asks for the time of the newest
report and fetches new reports only when that has moved. New rows are highlighted, an
open report stays open, and "Live: off" stops it. Polling pauses while the tab is in the
background.

The page loads all reports into the browser: 500 per request from D1, 40 from KV (the
free Workers plan allows 50 subrequests per request, and every KV read is one). With KV
a new report can take up to a minute to appear and costs two writes.

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
