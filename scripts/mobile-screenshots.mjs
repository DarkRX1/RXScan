// Headless-Chromium capture for RXScan mobile verification.
//
// Drives Chromium over the DevTools protocol, so it needs no npm packages.
// Per viewport it records a dashboard shot, a graph shot with nodes drawn, a
// detail bottom-sheet shot, and whether the document scrolls horizontally
// (documentElement.scrollWidth <= innerWidth).
//
// Usage:
//   cargo run --example mobseed -- /tmp/rxscan-mobseed
//   rxscan web --port 8918 --data-dir /tmp/rxscan-mobseed --no-open &
//   node scripts/mobile-screenshots.mjs http://127.0.0.1:8918 docs
//
// The seeded fixture uses reserved ranges and example domains only; nothing
// here scans or contacts anything outside loopback.

import { spawn } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';

const BASE = process.argv[2];
const OUT = process.argv[3];
const PORT = 9222;

const VIEWPORTS = [
  { name: '360x800', width: 360, height: 800 },
  { name: '390x844', width: 390, height: 844 },
  { name: '430x932', width: 430, height: 932 },
  { name: '768x1024', width: 768, height: 1024 },
];

mkdirSync(OUT, { recursive: true });

const chrome = spawn('chromium', [
  '--headless=new',
  `--remote-debugging-port=${PORT}`,
  '--no-sandbox',
  '--disable-gpu',
  '--hide-scrollbars',
  '--force-device-scale-factor=1',
  '--user-data-dir=/tmp/opencode/chrome-profile',
  'about:blank',
], { stdio: 'ignore' });

async function cdpTarget() {
  for (let i = 0; i < 100; i++) {
    try {
      const res = await fetch(`http://127.0.0.1:${PORT}/json/list`);
      const list = await res.json();
      const page = list.find((t) => t.type === 'page');
      if (page) return page.webSocketDebuggerUrl;
    } catch {}
    await sleep(200);
  }
  throw new Error('chromium devtools endpoint never came up');
}

const wsUrl = await cdpTarget();
const ws = new WebSocket(wsUrl);
await new Promise((res, rej) => {
  ws.onopen = res;
  ws.onerror = rej;
});

let nextId = 1;
const pending = new Map();
ws.onmessage = (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
  }
};

function send(method, params = {}) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
}

async function evaluate(expression) {
  const res = await send('Runtime.evaluate', {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  if (res.exceptionDetails) {
    throw new Error('page eval failed: ' + JSON.stringify(res.exceptionDetails));
  }
  return res.result.value;
}

async function shot(file) {
  const { data } = await send('Page.captureScreenshot', { format: 'png' });
  writeFileSync(`${OUT}/${file}`, Buffer.from(data, 'base64'));
}

const noOverflow = `document.documentElement.scrollWidth <= window.innerWidth`;
const nodeSel = `#graph-canvas .gnode-wrap`;

await send('Page.enable');
await send('Runtime.enable');

const report = [];

for (const vp of VIEWPORTS) {
  await send('Emulation.setDeviceMetricsOverride', {
    width: vp.width,
    height: vp.height,
    deviceScaleFactor: 1,
    mobile: vp.width < 768,
  });

  // Full reload (not just a hash change) so no prior viewport's sheet
  // or loaded graph leaks into this one.
  await send('Page.navigate', { url: `${BASE}/#/dashboard` });
  await sleep(1500);
  await send('Page.reload', { ignoreCache: false });
  await sleep(2500);
  await evaluate(`window.location.hash = '#/dashboard'`);
  await sleep(1500);
  await shot(`screenshot_${vp.name}_dashboard.png`);
  const dashOverflow = await evaluate(noOverflow);
  report.push({ vp: vp.name, kind: 'dashboard', noOverflow: dashOverflow });

  await evaluate(`window.location.hash = '#/graph'`);
  await sleep(2000);
  // The graph view requires an explicit load before nodes are drawn.
  await evaluate(`(()=>{
    const btn = [...document.querySelectorAll('#view-graph button')]
      .find(b => /load graph/i.test(b.textContent));
    if (btn) btn.click();
    return !!btn;
  })()`);
  await sleep(3500);
  // Scroll the canvas into view: on phones it sits below the fold.
  await evaluate(`(()=>{
    const c = document.getElementById('graph-canvas');
    if (c) c.scrollIntoView({block:'center'});
    return true;
  })()`);
  await sleep(1200);
  const nodeCount = await evaluate(`document.querySelectorAll('${nodeSel}').length`);
  await shot(`screenshot_${vp.name}_graph.png`);
  const graphOverflow = await evaluate(noOverflow);
  report.push({ vp: vp.name, kind: 'graph', noOverflow: graphOverflow, nodes: nodeCount });

  let sheet = 'unreachable';
  let sheetOverflow = null;
  try {
    const clicked = await evaluate(`(()=>{
      const n = document.querySelector('${nodeSel}');
      if (!n) return false;
      n.dispatchEvent(new MouseEvent('click', {bubbles:true}));
      return true;
    })()`);
    await sleep(1500);
    const state = await evaluate(`(()=>{
      const s = document.getElementById('bottom-sheet');
      if (!s) return 'no-element';
      if (s.hidden) return 'hidden';
      return s.className;
    })()`);
    if (clicked && state !== 'hidden' && state !== 'no-element') {
      await evaluate(`(()=>{window.scrollTo(0,0);return true;})()`);
      await sleep(600);
      await shot(`screenshot_${vp.name}_sheet.png`);
      sheetOverflow = await evaluate(noOverflow);
      sheet = state;
    } else {
      sheet = `not-opened(${state})`;
    }
    // Close the sheet so the next viewport starts clean.
    await evaluate(`(()=>{
      const c = document.querySelector('#bottom-sheet .bottom-sheet-close');
      if (c) c.click();
      return !!c;
    })()`);
    await sleep(400);
  } catch (e) {
    sheet = `error:${e.message}`;
  }
  report.push({ vp: vp.name, kind: 'sheet', noOverflow: sheetOverflow, state: sheet });

  console.log(
    `${vp.name}: dashboard_no_overflow=${dashOverflow} graph_no_overflow=${graphOverflow} nodes=${nodeCount} sheet=${sheet}`
  );
}

writeFileSync(`${OUT}/overflow-report.json`, JSON.stringify(report, null, 2));
ws.close();
chrome.kill();
console.log('DONE');
process.exit(0);