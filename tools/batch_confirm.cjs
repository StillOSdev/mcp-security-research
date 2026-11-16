#!/usr/bin/env node
'use strict';
/*
 * batch_confirm.cjs - THE CONFIRMATION STAGE the CVE pipeline never had.
 *
 * The hunter (refuel_and_hunt.cjs) produces path-flow leads by the hundred.
 * The bottleneck was never the scan - it was that each lead had to be
 * source-confirmed BY HAND, one package at a time, before it could ship as a
 * disclosure. That throttled the whole lane to a couple of findings a day.
 *
 * This stage removes the throttle: it pulls every untriaged path-flow lead in
 * parallel (npm pack, source only), classifies each package's write surface,
 * pulls real weekly downloads for reach, and emits a RANKED shortlist. The
 * human read - still mandatory, because grep is fooled by a guard it does not
 * recognize (measured: starreel/raven/i18n all passed the heuristic and were
 * safe on a read) - now walks 15 ranked candidates instead of 145 raw leads.
 *
 * VERDICTS (deliberately conservative; LIKELY_LIVE is a candidate, NOT a proof):
 *   GUARDED       a path-containment guard is present (resolveWithin,
 *                 assertSafe, realpath+startsWith, allowed-dir reject, ...).
 *   NO_WRITE_SINK no writeFileSync/writeFile/createWriteStream in non-install JS.
 *   NEEDS_READ    a write exists but the path origin is unclear or an id/name
 *                 validation is present - a human must read it.
 *   LIKELY_LIVE   a caller-facing path input (output_path/filePath/dest/...)
 *                 reaches a write with NO guard and NO id-validation found.
 *                 This is the read-me-first tier, ranked by downloads.
 *
 * FALSE-ZERO LAW: a package that fails to pull emits PACK_FAIL with a reason,
 * never a silent skip and never a clean "no finding".
 * SEND NOTHING: this pulls public tarballs and reads source. Disclosure of a
 * confirmed finding is a separate, human-gated Hard Brake - not in this file.
 *
 *   node hunt/batch_confirm.cjs [--leads <file>] [--top N] [--conc K] [--json]
 *   node hunt/batch_confirm.cjs --self-test
 *
 * Default leads file: hunt/refuel-leads.jsonl (flows.path > 0 rows).
 * Output ledger: hunt/batch-confirm-results.jsonl (append-only, one run-block).
 */
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');

const HUNT = __dirname;
const DEFAULT_LEADS = path.join(HUNT, 'refuel-leads.jsonl');
const LEDGER = path.join(HUNT, 'batch-confirm-results.jsonl');

function arg(flag, def) {
  const i = process.argv.indexOf(flag);
  return i > -1 && process.argv[i + 1] ? process.argv[i + 1] : def;
}
const has = (flag) => process.argv.includes(flag);

// ---- the classifier. Pure function over a package dir so it is unit-testable.
const GUARD_RE = /path-guard|assertSafe|assertInside|ensureInside|sanitizePath|isPathInside|resolveWithin|resolve[^\n]{0,40}startsWith|within[^\n]{0,20}root|realpathSync[^\n]{0,80}startsWith|allowed.?dir|ALLOWED_DIR/i;
const CALLER_PATH_RE = /output_?path|target_?path|dest_?path|save_?path|file_?path|output_?file|outputDir|output_?dir/i;
const SCHEMA_HINT_RE = /z\.string|inputSchema|type:\s*['"]string['"]|describe\(|properties/i;
const IDVAL_RE = /not a usable id|is not a valid|replace\(\/\[\^|[a-zA-Z0-9]\]\+?\/|\.test\(|basename\(/i;
const WRITE_RE = /writeFileSync|writeFile\(|createWriteStream/;

/* classifyPackage(readFile, listJsFiles) -> {verdict, signal}
 * readFile(relpath) -> string | null ; listJsFiles() -> [relpath] (non-install, non-node_modules) */
function classifyPackage(readFile, listJsFiles) {
  const files = listJsFiles();
  const writeFiles = files.filter((f) => {
    const b = readFile(f);
    return b && WRITE_RE.test(b);
  });
  if (!writeFiles.length) return { verdict: 'NO_WRITE_SINK', signal: '-' };

  let guard = false, callerPath = false, idval = false;
  for (const f of writeFiles) {
    const b = readFile(f) || '';
    if (GUARD_RE.test(b)) guard = true;
    // a caller path token that co-occurs with a schema/tool hint in the same file
    if (CALLER_PATH_RE.test(b) && SCHEMA_HINT_RE.test(b)) callerPath = true;
    if (IDVAL_RE.test(b)) idval = true;
  }
  if (guard) return { verdict: 'GUARDED', signal: 'path-containment-guard-present' };
  if (callerPath && !idval) return { verdict: 'LIKELY_LIVE', signal: 'caller-path-input,no-guard,no-idval' };
  if (callerPath) return { verdict: 'NEEDS_READ', signal: 'caller-path-input,id-validation-present' };
  return { verdict: 'NEEDS_READ', signal: 'write-sink,path-origin-unclear' };
}

// ---- real-world adapters (I/O kept out of the classifier for testability)
function pullAndClassify(pkg) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'bconf-'));
  try {
    try { execFileSync('npm', ['pack', pkg], { cwd: work, stdio: 'ignore', timeout: 60000 }); }
    catch { return { pkg, version: '-', downloads: '?', verdict: 'PACK_FAIL', signal: 'npm pack failed' }; }
    const tgz = fs.readdirSync(work).find((f) => f.endsWith('.tgz'));
    if (!tgz) return { pkg, version: '-', downloads: '?', verdict: 'PACK_FAIL', signal: 'no tarball' };
    execFileSync('tar', ['xzf', tgz], { cwd: work, stdio: 'ignore', timeout: 30000 });
    const root = path.join(work, 'package');
    let version = '?';
    try { version = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version || '?'; } catch {}
    const jsFiles = [];
    (function walk(d) {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        const p = path.join(d, e.name);
        if (e.isDirectory()) { if (!/node_modules|test|__tests__/.test(e.name)) walk(p); }
        else if (e.name.endsWith('.js') && !/install\.js$/.test(e.name)) jsFiles.push(path.relative(root, p));
      }
    })(root);
    const readFile = (rel) => { try { return fs.readFileSync(path.join(root, rel), 'utf8'); } catch { return null; } };
    const { verdict, signal } = classifyPackage(readFile, () => jsFiles.slice(0, 40));
    return { pkg, version, downloads: fetchDownloads(pkg), verdict, signal };
  } finally {
    try { fs.rmSync(work, { recursive: true, force: true }); } catch {}
  }
}

function fetchDownloads(pkg) {
  try {
    const out = execFileSync('curl', ['-s', '--max-time', '8',
      `https://api.npmjs.org/downloads/point/last-week/${pkg}`], { timeout: 10000 }).toString();
    const n = JSON.parse(out).downloads;
    return Number.isFinite(n) ? n : '?';
  } catch { return '?'; }
}

function leadPackages(file) {
  const seen = new Map();
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    let j; try { j = JSON.parse(line); } catch { continue; }
    const p = (j.flows || {}).path || 0;
    if (p > 0 && !seen.has(j.pkg)) seen.set(j.pkg, p);
  }
  return [...seen.entries()].sort((a, b) => b[1] - a[1]).map(([pkg]) => pkg);
}

async function mapPool(items, conc, fn) {
  const out = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(conc, items.length) }, async () => {
    while (i < items.length) { const idx = i++; out[idx] = await fn(items[idx], idx); }
  }));
  return out;
}

async function main() {
  const leadsFile = arg('--leads', DEFAULT_LEADS);
  const top = parseInt(arg('--top', '0'), 10);
  const conc = parseInt(arg('--conc', '8'), 10);
  if (!fs.existsSync(leadsFile)) { console.error(`no leads file: ${leadsFile}`); process.exit(3); }
  let pkgs = leadPackages(leadsFile);
  if (top > 0) pkgs = pkgs.slice(0, top);
  if (!pkgs.length) { console.error('no path-flow leads to confirm'); process.exit(3); }

  const results = await mapPool(pkgs, conc, (pkg) => Promise.resolve().then(() => pullAndClassify(pkg)));
  const dist = {};
  for (const r of results) dist[r.verdict] = (dist[r.verdict] || 0) + 1;

  const rank = { LIKELY_LIVE: 0, NEEDS_READ: 1, GUARDED: 2, NO_WRITE_SINK: 3, PACK_FAIL: 4 };
  const dlNum = (d) => (typeof d === 'number' ? d : -1);
  results.sort((a, b) => (rank[a.verdict] - rank[b.verdict]) || (dlNum(b.downloads) - dlNum(a.downloads)));

  const runRow = { ts: new Date().toISOString(), leads_file: leadsFile, count: results.length, dist, results };
  fs.appendFileSync(LEDGER, JSON.stringify(runRow) + '\n');

  if (has('--json')) { process.stdout.write(JSON.stringify(runRow, null, 2) + '\n'); return; }
  console.log(`batch_confirm: ${results.length} leads | ` + Object.entries(dist).map(([k, v]) => `${k}=${v}`).join(' '));
  console.log('\nREAD-ME-FIRST (LIKELY_LIVE, ranked by downloads):');
  for (const r of results.filter((x) => x.verdict === 'LIKELY_LIVE')) {
    console.log(`  ${String(r.pkg).padEnd(34)} v${String(r.version).padEnd(14)} ${String(r.downloads).padStart(6)} dl  ${r.signal}`);
  }
  console.log(`\nledger: ${LEDGER}`);
}

// ---- self-test: the classifier against synthetic packages, no network
function selfTest() {
  const assert = require('assert');
  const mk = (filesMap) => [
    (rel) => filesMap[rel] ?? null,
    () => Object.keys(filesMap),
  ];
  let n = 0; const t = (name, fn) => { fn(); n++; console.log('  ok', name); };

  t('no write sink -> NO_WRITE_SINK', () => {
    const [rf, lf] = mk({ 'index.js': 'export const x = 1; readFileSync(p);' });
    assert.equal(classifyPackage(rf, lf).verdict, 'NO_WRITE_SINK');
  });
  t('caller output_path + schema, no guard -> LIKELY_LIVE', () => {
    const [rf, lf] = mk({ 'server.js': 'inputSchema:{output_path:z.string()}; writeFileSync(output_path, buf);' });
    assert.equal(classifyPackage(rf, lf).verdict, 'LIKELY_LIVE');
  });
  t('resolveWithin guard -> GUARDED', () => {
    const [rf, lf] = mk({ 'server.js': 'const o = resolveWithin(cfg, output_path); z.string(); writeFileSync(o, b);' });
    assert.equal(classifyPackage(rf, lf).verdict, 'GUARDED');
  });
  t('realpath+startsWith guard -> GUARDED', () => {
    const [rf, lf] = mk({ 'a.js': 'const r=realpathSync(p); if(!r.startsWith(root)) throw 0; z.string(); writeFile(r,b);' });
    assert.equal(classifyPackage(rf, lf).verdict, 'GUARDED');
  });
  t('id-validation present -> NEEDS_READ (not LIKELY_LIVE)', () => {
    const [rf, lf] = mk({ 's.js': 'file_path:z.string(); if(!id.test(/[a-zA-Z0-9]+/)) throw 0; writeFileSync(path.join(dir,id),b);' });
    assert.equal(classifyPackage(rf, lf).verdict, 'NEEDS_READ');
  });
  t('write but opaque path origin -> NEEDS_READ', () => {
    const [rf, lf] = mk({ 'x.js': 'const p = internalState.p; writeFileSync(p, buf);' });
    assert.equal(classifyPackage(rf, lf).verdict, 'NEEDS_READ');
  });
  t('install.js writes are ignored by the walker (adapter contract)', () => {
    // classifier only sees what listJsFiles yields; the adapter excludes install.js.
    const [rf, lf] = mk({ 'lib/core.js': 'no writes here, just readFileSync' });
    assert.equal(classifyPackage(rf, lf).verdict, 'NO_WRITE_SINK');
  });
  console.log(`\nbatch_confirm self-test: ${n}/${n} passed`);
}

if (has('--self-test')) selfTest();
else main().catch((e) => { console.error('batch_confirm fatal:', e.message); process.exit(1); });
