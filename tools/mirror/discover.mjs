#!/usr/bin/env node
// Opens the site's pages in a real browser, scrolls and clicks through them and
// records every URL the pages request. Also saves full-page screenshots of the
// original pages for later comparison.
//
//   node discover.mjs --origin https://sulba.site --out discovered.json --shots shots/

import { chromium } from 'playwright';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

const args = {};
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i];
  if (a.startsWith('--')) args[a.slice(2)] = process.argv[i + 1] && !process.argv[i + 1].startsWith('--') ? process.argv[++i] : 'true';
}
const ORIGIN = new URL(args.origin || 'https://sulba.site');
const PAGES = (args.pages || '/,/research.html').split(',');
const OUT = path.resolve(args.out || 'discovered.json');
const SHOTS = args.shots ? path.resolve(args.shots) : null;
const CLICK_LIMIT = Number(args['click-limit'] || 160);

const seen = new Map();
const external = new Map();
const problems = [];

function record(rawUrl, type, page) {
  let u;
  try { u = new URL(rawUrl); } catch { return; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
  u.hash = '';
  if (u.host === ORIGIN.host) {
    if (!seen.has(u.href)) seen.set(u.href, { type, page });
  } else {
    if (!external.has(u.host)) external.set(u.host, new Set());
    const set = external.get(u.host);
    if (set.size < 15) set.add(u.href);
  }
}

async function autoScroll(page) {
  await page.evaluate(async () => {
    const step = Math.max(300, Math.floor(window.innerHeight * 0.8));
    for (let y = 0; y < document.documentElement.scrollHeight + step; y += step) {
      window.scrollTo(0, y);
      await new Promise((r) => setTimeout(r, 150));
    }
    window.scrollTo(0, 0);
  }).catch(() => {});
}

async function clickAround(page) {
  const selector = [
    'button', '[role="button"]', '[role="tab"]', 'summary', 'a[href^="#"]', '[aria-controls]',
    '[data-open]', '[data-action]', '[data-page]', '[data-filter]', '[data-tab]', '[data-step]',
  ].join(', ');
  const startUrl = page.url().split('#')[0];
  const total = Math.min(await page.locator(selector).count().catch(() => 0), CLICK_LIMIT);
  for (let i = 0; i < total; i++) {
    const el = page.locator(selector).nth(i);
    try {
      await el.click({ timeout: 600 });
      await page.waitForTimeout(120);
    } catch { /* hidden or covered element */ }
    if (page.url().split('#')[0] !== startUrl) {
      await page.goto(startUrl, { waitUntil: 'domcontentloaded', timeout: 30000 }).catch(() => {});
    }
    if (i % 4 === 3) await page.keyboard.press('Escape').catch(() => {});
  }
}

const launchOptions = { headless: true };
if (process.env.PW_EXECUTABLE) launchOptions.executablePath = process.env.PW_EXECUTABLE;
const browser = await chromium.launch(launchOptions);

const profiles = [
  { name: 'desktop', options: { viewport: { width: 1366, height: 900 } }, click: true },
  {
    name: 'mobile',
    options: {
      viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true,
      userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
    },
    click: false,
  },
];

if (SHOTS) await mkdir(SHOTS, { recursive: true });

for (const profile of profiles) {
  const context = await browser.newContext({ ...profile.options, locale: 'kk-KZ', serviceWorkers: 'block', acceptDownloads: false });
  await context.addInitScript(() => { window.print = () => {}; window.open = () => null; });
  for (const p of PAGES) {
    const page = await context.newPage();
    page.on('request', (r) => record(r.url(), r.resourceType(), p));
    page.on('pageerror', (e) => problems.push({ page: p, profile: profile.name, error: String(e).slice(0, 300) }));
    page.on('console', (m) => { if (m.type() === 'error') problems.push({ page: p, profile: profile.name, console: m.text().slice(0, 300) }); });
    page.on('requestfailed', (r) => problems.push({ page: p, profile: profile.name, failed: r.url().slice(0, 200), reason: r.failure()?.errorText }));
    page.on('dialog', (d) => d.dismiss().catch(() => {}));
    try {
      await page.goto(ORIGIN.origin + p, { waitUntil: 'networkidle', timeout: 90000 });
    } catch (err) {
      problems.push({ page: p, profile: profile.name, goto: String(err?.message || err).slice(0, 300) });
    }
    await autoScroll(page);
    await page.waitForTimeout(1500);
    if (SHOTS) {
      const slug = p === '/' ? 'index' : p.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '');
      await page.screenshot({ path: path.join(SHOTS, `orig-${slug}-${profile.name}.jpg`), fullPage: true, type: 'jpeg', quality: 62 })
        .catch((err) => problems.push({ page: p, profile: profile.name, screenshot: String(err?.message || err).slice(0, 200) }));
    }
    if (profile.click) {
      await clickAround(page);
      await page.waitForTimeout(4000);
    }
    const perf = await page.evaluate(() => performance.getEntriesByType('resource').map((e) => e.name)).catch(() => []);
    for (const name of perf) record(name, 'perf', p);
    await page.close();
  }
  await context.close();
}
await browser.close();

await mkdir(path.dirname(OUT), { recursive: true });
await writeFile(
  OUT,
  JSON.stringify({
    origin: ORIGIN.origin,
    generatedAt: new Date().toISOString(),
    urls: [...seen.keys()].sort(),
    requests: Object.fromEntries([...seen].sort()),
    external: Object.fromEntries([...external].sort().map(([h, s]) => [h, [...s]])),
    problems: problems.slice(0, 300),
  }, null, 1),
);
console.log(`browser discovery: ${seen.size} same-site urls, ${external.size} external hosts, ${problems.length} problems`);
