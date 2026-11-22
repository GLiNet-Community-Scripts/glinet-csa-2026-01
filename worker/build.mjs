// Turns src/dashboard.html into src/dashboard.js, the module the worker imports.
// Run it after every change to the page:  node build.mjs
import { readFileSync, writeFileSync } from 'node:fs';
const dir = new URL('./src/', import.meta.url);
// the list of known release files (tools/known-hashes.sh) goes into the page as it is
const known = JSON.stringify(JSON.parse(readFileSync(new URL('known-hashes.json', dir), 'utf8')));
const page = readFileSync(new URL('dashboard.html', dir), 'utf8');
if (!page.includes('/*KNOWN_HASHES*/{}')) throw new Error('dashboard.html has no place for the known hashes');
const html = page.replace('/*KNOWN_HASHES*/{}', () => known);
writeFileSync(
  new URL('dashboard.js', dir),
  '// Generated from dashboard.html by build.mjs. Do not edit; change the HTML and run "node build.mjs".\n' +
    `export const DASHBOARD = ${JSON.stringify(html)};\n`,
);
console.log(`dashboard.js written (${html.length} characters)`);
