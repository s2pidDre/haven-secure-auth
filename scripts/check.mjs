import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
function filesAt(path) {
  return readdirSync(path, { withFileTypes: true }).flatMap(entry => {
    if (['data', 'certs', 'node_modules', '.git'].includes(entry.name)) return [];
    const pathName = join(path, entry.name);
    return entry.isDirectory() ? filesAt(pathName) : [pathName];
  });
}
let failures = 0;
for (const file of filesAt('.').filter(file => /\.(mjs|js)$/.test(file))) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (result.status !== 0) { console.error(result.stderr); failures++; }
}
const layout = readFileSync('templates/layout.html', 'utf8');
for (const reference of ['/css/style.css', '/js/main.js']) {
  if (!layout.includes(reference) || !readFileSync(`public${reference}`).length) failures++;
}
for (const file of filesAt('templates').filter(file => file.endsWith('.html'))) {
  const html = readFileSync(file, 'utf8');
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
  if (new Set(ids).size !== ids.length) { console.error(`Duplicate ID in ${file}`); failures++; }
  for (const match of html.matchAll(/<form\b[^>]*method="post"[^>]*>([\s\S]*?)<\/form>/g)) {
    if (!match[1].includes('name="csrf"')) { console.error(`Missing CSRF field in ${file}`); failures++; }
  }
}
if (failures) { console.error(`${failures} check(s) failed.`); process.exitCode = 1; }
else console.log('JavaScript syntax, asset references, form CSRF fields, and template IDs passed.');
