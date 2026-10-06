// Drives one bench run in headless Chromium.
// Usage: node run.mjs <out.json> <task> <kps address> <calls> <gapMs> <bytes> <chunk>
import { chromium } from "playwright";
import http from "node:http";
import fs from "node:fs";

const [out, task, addr, calls, gapMs, bytes, chunk] = process.argv.slice(2);
const opts = { calls: Number(calls), gapMs: Number(gapMs), bytes: Number(bytes), chunk: Number(chunk) };
const js = fs.readFileSync(new URL("./dist/bench.js", import.meta.url));
const srv = http
  .createServer((req, res) => {
    if (req.url === "/bench.js") {
      res.writeHead(200, { "content-type": "text/javascript" });
      res.end(js);
      return;
    }
    res.writeHead(200, { "content-type": "text/html" });
    res.end('<!doctype html><script src="/bench.js"></script>');
  })
  .listen(0, "127.0.0.1");
await new Promise((r) => srv.once("listening", r));
const browser = await chromium.launch({ headless: true });
const page = await (await browser.newContext()).newPage();
page.on("console", (m) => process.stderr.write("[page] " + m.text() + "\n"));
await page.goto(`http://127.0.0.1:${srv.address().port}/`);
const started = new Date().toISOString();
const res = await page.evaluate(({ task, addr, opts }) => globalThis.KB[task](addr, opts), { task, addr, opts });
fs.writeFileSync(out, JSON.stringify({ chromium: browser.version(), started, task, opts, res }, null, 1));
await browser.close();
srv.close();
