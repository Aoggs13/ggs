#!/usr/bin/env node
// Static mirror of one website origin.
// Downloads every same-site file reachable from the seed pages and from URLs
// found inside HTML, CSS, JS and JSON files. Keeps the original paths.
//
//   node mirror.mjs --origin https://sulba.site --out out/site --report out/report
//   node mirror.mjs ... --extra discovered.json     (adds URLs found by discover.mjs)

import { createHash, randomBytes } from 'node:crypto';
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';

const args = parseArgs(process.argv.slice(2));
const ORIGIN = new URL(args.origin || 'https://sulba.site');
const OUT = path.resolve(args.out || 'out/site');
const REPORT = path.resolve(args.report || 'out/report');
const ALIAS_HOSTS = new Set(
  (args.alias ?? `www.${ORIGIN.hostname},sulba-kz.up.railway.app`).split(',').map((s) => s.trim()).filter(Boolean),
);
const MAX_FILES = Number(args['max-files'] || 4000);
const MAX_FILE_BYTES = Number(args['max-file-bytes'] || 300 * 1024 * 1024);
const MAX_TOTAL_BYTES = Number(args['max-total-bytes'] || 900 * 1024 * 1024);
const CONCURRENCY = Number(args.concurrency || 6);
const TIMEOUT_MS = Number(args['timeout-ms'] || 180000);
const UA =
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';

const ASSET_EXT =
  'png|jpe?g|webp|gif|svg|avif|ico|bmp|pdf|json|js|mjs|css|woff2?|ttf|otf|eot|mp4|webm|mov|m4v|mp3|ogg|wav|m4a|html?|txt|xml|webmanifest|map|wasm|csv|geojson|vtt|srt|zip';
const EXT_RE = new RegExp(`\\.(?:${ASSET_EXT})(?:[?#]|$)`, 'i');
const GENERIC_RE = new RegExp(`["'\`(]([^"'\`\\s<>{}$()?#]{1,400}\\.(?:${ASSET_EXT}))([?#][^"'\`\\s)]*)?["'\`)]`, 'gi');

const DEFAULT_SEEDS = [
  '/', '/index.html', '/research.html', '/robots.txt', '/sitemap.xml', '/favicon.ico', '/favicon.svg',
  '/favicon.png', '/apple-touch-icon.png', '/manifest.json', '/manifest.webmanifest', '/site.webmanifest',
  '/sw.js', '/service-worker.js', '/404.html',
];

const entries = new Map(); // pathname -> entry
const queue = [];
const externalRefs = new Map(); // host -> Set(example urls)
const fallbackHashes = new Set();
let totalBytes = 0;
let savedCount = 0;

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) out[key] = 'true';
    else { out[key] = next; i++; }
  }
  return out;
}

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

function isTextType(type, pathname) {
  const t = (type || '').toLowerCase();
  if (/^text\/|javascript|json|xml|svg|manifest|ecmascript/.test(t)) return true;
  return /\.(?:html?|css|m?js|json|svg|xml|txt|webmanifest|map|csv|geojson|vtt|srt)$/i.test(pathname);
}

function kindOf(type, pathname) {
  const t = (type || '').toLowerCase();
  if (t.includes('html') || /\.html?$/i.test(pathname)) return 'html';
  if (t.includes('css') || /\.css$/i.test(pathname)) return 'css';
  return 'other';
}

// ---- reference extraction (pure functions, exported for tests) ----

export function extractRefs(text, kind) {
  const refs = new Set();
  const add = (v) => { if (v) refs.add(v.trim()); };
  if (kind === 'html') {
    const attrRe = /\b(href|src|poster|action|content|data-[\w-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/gi;
    for (const m of text.matchAll(attrRe)) {
      const name = m[1].toLowerCase();
      const value = m[2] ?? m[3] ?? '';
      if (name === 'content' || name.startsWith('data-')) {
        if (/^(?:https?:)?\/\//i.test(value) || /^\.{0,2}\//.test(value) || EXT_RE.test(value)) add(value);
      } else add(value);
    }
    const srcsetRe = /\b(?:srcset|imagesrcset|data-srcset)\s*=\s*(?:"([^"]*)"|'([^']*)')/gi;
    for (const m of text.matchAll(srcsetRe)) {
      for (const part of (m[1] ?? m[2] ?? '').split(',')) add(part.trim().split(/\s+/)[0]);
    }
  }
  if (kind === 'html' || kind === 'css') {
    const urlRe = /url\(\s*(?:"([^"]*)"|'([^']*)'|([^)\s]+))\s*\)/gi;
    for (const m of text.matchAll(urlRe)) add(m[1] ?? m[2] ?? m[3]);
    const importRe = /@import\s+(?:"([^"]*)"|'([^']*)')/gi;
    for (const m of text.matchAll(importRe)) add(m[1] ?? m[2]);
  }
  for (const m of text.matchAll(GENERIC_RE)) add(m[1] + (m[2] ?? ''));
  return [...refs].filter((r) => r && !/^(?:data:|blob:|javascript:|mailto:|tel:|about:|#)/i.test(r));
}

export function resolveRef(ref, bases) {
  const out = [];
  for (const base of bases) {
    try {
      const u = new URL(ref, base);
      if (u.protocol === 'http:' || u.protocol === 'https:') { u.hash = ''; out.push(u); }
    } catch { /* not a URL */ }
  }
  return out;
}

export function savePathFor(outDir, pathname, type) {
  let p;
  try { p = decodeURIComponent(pathname); } catch { p = pathname; }
  if (p.includes('\0')) throw new Error('bad path');
  p = path.posix.normalize(p.startsWith('/') ? p : '/' + p);
  if (p.endsWith('/')) p += 'index.html';
  else if (!path.posix.extname(p) && /html/i.test(type || '')) p += '.html';
  const full = path.join(outDir, p);
  if (full !== outDir && !full.startsWith(outDir + path.sep)) throw new Error('path escapes output dir');
  return full;
}

// ---- crawl ----

function isSameSite(u) {
  return u.host === ORIGIN.host || ALIAS_HOSTS.has(u.hostname);
}

function enqueueUrl(u, from) {
  if (!isSameSite(u)) {
    if (!externalRefs.has(u.host)) externalRefs.set(u.host, new Set());
    const set = externalRefs.get(u.host);
    if (set.size < 12) set.add(u.href);
    return;
  }
  const pathname = u.pathname || '/';
  let entry = entries.get(pathname);
  if (!entry) {
    if (entries.size >= MAX_FILES) return;
    entry = { path: pathname, search: u.search || '', from: [], status: null, saved: false };
    entries.set(pathname, entry);
    queue.push(entry);
  }
  if (from && entry.from.length < 6 && !entry.from.includes(from)) entry.from.push(from);
}

async function fetchWithRetry(url) {
  let lastError;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const res = await fetch(url, {
        headers: { 'user-agent': UA, accept: '*/*', 'accept-language': 'kk,ru;q=0.8,en;q=0.6' },
        redirect: 'follow',
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if ((res.status >= 500 || res.status === 429) && attempt < 2) {
        await res.arrayBuffer().catch(() => {});
        await sleep(1500 * (attempt + 1));
        continue;
      }
      return res;
    } catch (err) {
      lastError = err;
      await sleep(1500 * (attempt + 1));
    }
  }
  throw lastError ?? new Error('fetch failed');
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function processEntry(entry) {
  const url = ORIGIN.origin + entry.path + entry.search;
  let res;
  try {
    res = await fetchWithRetry(url);
  } catch (err) {
    entry.status = 0;
    entry.error = String(err?.message || err).slice(0, 200);
    return;
  }
  entry.status = res.status;
  entry.type = res.headers.get('content-type') || '';
  entry.finalUrl = res.url !== url ? res.url : undefined;
  if (!res.ok) { await res.arrayBuffer().catch(() => {}); return; }

  const declared = Number(res.headers.get('content-length') || 0);
  if (declared > MAX_FILE_BYTES) { entry.error = `too large (${declared} bytes)`; await res.body?.cancel().catch(() => {}); return; }
  let finalUrl;
  try { finalUrl = new URL(res.url); } catch { finalUrl = new URL(url); }
  if (!isSameSite(finalUrl)) { entry.error = `redirected off-site to ${finalUrl.host}`; await res.body?.cancel().catch(() => {}); return; }

  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > MAX_FILE_BYTES) { entry.error = `too large (${buf.length} bytes)`; return; }
  entry.bytes = buf.length;
  entry.sha256 = sha256(buf);

  const isRoot = entry.path === '/' || entry.path === '/index.html';
  if (!isRoot && fallbackHashes.has(entry.sha256)) { entry.error = 'same body as the not-found page (fallback)'; return; }
  if (!isRoot && /html/i.test(entry.type) && !/\.html?$/i.test(entry.path) && path.posix.extname(entry.path)) {
    entry.error = 'HTML returned for a non-HTML path (fallback)';
    return;
  }
  if (totalBytes + buf.length > MAX_TOTAL_BYTES) { entry.error = 'total size limit reached'; return; }

  const file = savePathFor(OUT, entry.path, entry.type);
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, buf);
  entry.saved = true;
  entry.file = path.relative(OUT, file).split(path.sep).join('/');
  totalBytes += buf.length;
  savedCount++;

  if (isTextType(entry.type, entry.path) && buf.length < 30 * 1024 * 1024) {
    const text = buf.toString('utf8');
    const kind = kindOf(entry.type, entry.path);
    const selfUrl = ORIGIN.origin + entry.path;
    const bases = kind === 'other' ? [selfUrl, ORIGIN.origin + '/'] : [selfUrl];
    for (const ref of extractRefs(text, kind)) {
      for (const u of resolveRef(ref, bases)) enqueueUrl(u, entry.path);
    }
  }
}

async function probeFallback() {
  for (const ext of ['.html', '.txt', '.png', '']) {
    const probe = `${ORIGIN.origin}/__mirror_probe_${randomBytes(6).toString('hex')}${ext}`;
    try {
      const res = await fetchWithRetry(probe);
      const buf = Buffer.from(await res.arrayBuffer());
      if (res.ok && buf.length) fallbackHashes.add(sha256(buf));
      console.log(`probe ${ext || '(no ext)'} -> ${res.status}, ${buf.length} bytes`);
    } catch (err) {
      console.log(`probe ${ext} failed: ${err?.message || err}`);
    }
  }
}

async function loadPrevious() {
  const file = path.join(REPORT, 'manifest.json');
  if (!existsSync(file)) return;
  const prev = JSON.parse(await readFile(file, 'utf8'));
  for (const e of prev.entries || []) {
    entries.set(e.path, e);
    if (e.saved) { totalBytes += e.bytes || 0; savedCount++; }
  }
  for (const [host, list] of Object.entries(prev.external || {})) externalRefs.set(host, new Set(list));
  for (const h of prev.fallbackHashes || []) fallbackHashes.add(h);
  console.log(`loaded previous manifest: ${entries.size} entries, ${savedCount} saved`);
}

async function main() {
  await mkdir(OUT, { recursive: true });
  await mkdir(REPORT, { recursive: true });
  await loadPrevious();
  if (!fallbackHashes.size) await probeFallback();

  const seeds = [...DEFAULT_SEEDS, ...(args.seeds ? args.seeds.split(',') : [])];
  for (const s of seeds) for (const u of resolveRef(s, [ORIGIN.origin + '/'])) enqueueUrl(u, '(seed)');
  if (args.extra && existsSync(args.extra)) {
    const extra = JSON.parse(await readFile(args.extra, 'utf8'));
    for (const raw of extra.urls || []) for (const u of resolveRef(raw, [ORIGIN.origin + '/'])) enqueueUrl(u, '(browser)');
    console.log(`extra urls from browser discovery: ${(extra.urls || []).length}`);
  }

  let active = 0;
  await new Promise((resolve) => {
    const pump = () => {
      if (!queue.length && active === 0) return resolve();
      while (active < CONCURRENCY && queue.length) {
        const entry = queue.shift();
        active++;
        processEntry(entry)
          .catch((err) => { entry.status = entry.status ?? 0; entry.error = String(err?.message || err).slice(0, 200); })
          .finally(() => { active--; pump(); });
      }
    };
    pump();
  });

  const list = [...entries.values()].sort((a, b) => a.path.localeCompare(b.path));
  const external = Object.fromEntries([...externalRefs].sort().map(([h, s]) => [h, [...s]]));
  await writeFile(
    path.join(REPORT, 'manifest.json'),
    JSON.stringify({ origin: ORIGIN.origin, generatedAt: new Date().toISOString(), totalBytes, savedCount, fallbackHashes: [...fallbackHashes], entries: list, external }, null, 1),
  );

  const saved = list.filter((e) => e.saved);
  const failed = list.filter((e) => !e.saved);
  const lines = [];
  lines.push(`origin: ${ORIGIN.origin}`, `generated: ${new Date().toISOString()}`, `saved files: ${saved.length}`, `total bytes: ${totalBytes}`, `not saved: ${failed.length}`, '');
  lines.push('== saved (bytes, type, path) ==');
  for (const e of saved) lines.push(`${String(e.bytes).padStart(10)}  ${(e.type || '').split(';')[0].padEnd(28)} ${e.file}`);
  lines.push('', '== not saved (status, path, reason, referenced from) ==');
  for (const e of failed) lines.push(`${String(e.status).padStart(4)}  ${e.path}  ${e.error || ''}  <- ${e.from.join(', ')}`);
  lines.push('', '== external hosts referenced ==');
  for (const [h, urls] of Object.entries(external)) lines.push(`${h}: ${urls.slice(0, 4).join('  ')}`);
  await writeFile(path.join(REPORT, 'summary.txt'), lines.join('\n') + '\n');

  console.log(`saved ${saved.length} files, ${totalBytes} bytes; not saved ${failed.length}`);
  const root = entries.get('/');
  if (!root?.saved) { console.error(`root page was not saved (status ${root?.status}, ${root?.error || ''})`); process.exitCode = 2; }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  main().catch((err) => { console.error(err); process.exitCode = 1; });
}
