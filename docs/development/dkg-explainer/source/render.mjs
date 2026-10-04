import { chromium } from '/opt/node22/lib/node_modules/playwright/index.mjs';
import fs from 'fs';
const [mode, a, b] = process.argv.slice(2);
const tl = JSON.parse(fs.readFileSync('timeline.json'));
const html = fs.readFileSync('scene.html','utf8').replace('<script>', `<script>window.TIMELINE=${JSON.stringify(tl)};</script><script>`);
fs.writeFileSync('scene_built.html', html);
const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome' });
const page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });
await page.goto('file://' + process.cwd() + '/scene_built.html');
const el = await page.$('#stage');
if (mode === 'stills') {
  fs.mkdirSync('stills', { recursive: true });
  let n = 0;
  for (const s of tl.scenes) for (const bt of s.beats) {
    const t = bt.speechEnd + 0.1;
    await page.evaluate(t => renderAt(t), t);
    await el.screenshot({ path: `stills/${String(n++).padStart(2,'0')}.png` });
  }
} else {
  const FPS = 30; const start = +a, end = +b;
  fs.mkdirSync('frames', { recursive: true });
  for (let f = start; f < end; f++) {
    await page.evaluate(t => renderAt(t), f / FPS);
    await el.screenshot({ path: `frames/${String(f).padStart(6,'0')}.jpg`, type: 'jpeg', quality: 92 });
  }
}
await browser.close();
