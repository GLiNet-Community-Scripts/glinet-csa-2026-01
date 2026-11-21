// Turns src/dashboard.html into src/dashboard.js, the module the worker imports.
// Run it after every change to the page:  node build.mjs
import { readFileSync, writeFileSync } from 'node:fs';
const dir = new URL('./src/', import.meta.url);
const html = readFileSync(new URL('dashboard.html', dir), 'utf8');
writeFileSync(
  new URL('dashboard.js', dir),
  '// Generated from dashboard.html by build.mjs. Do not edit; change the HTML and run "node build.mjs".\n' +
    `export const DASHBOARD = ${JSON.stringify(html)};\n`,
);
console.log(`dashboard.js written (${html.length} characters)`);
