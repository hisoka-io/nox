// Browser side of the nox-kps latency bench. Bundled with esbuild and loaded
// into headless Chromium by run.mjs; exposes globalThis.KB. All times are
// performance.now() deltas in ms.
import { dial } from "@kpstreams/webrtc-client";

type Opts = { calls: number; gapMs: number; bytes: number; chunk: number };

const enc = new TextEncoder();
const certhashOf = (addr: string) => addr.slice(addr.lastIndexOf(":") + 1);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// One HTTP/1.1 exchange on a fresh KPS stream, timed from the first write.
async function exchange(conn: any, addr: string, method: string, path: string, body: Uint8Array | null, chunk: number) {
  const t = performance.now();
  const s = await conn.openStream();
  let head = `${method} ${path} HTTP/1.1\r\nHost: ${certhashOf(addr)}\r\nUser-Agent: kps-latency-bench\r\n`;
  if (body) head += `Content-Type: application/json\r\nContent-Length: ${body.length}\r\n`;
  head += "\r\n";
  const h = enc.encode(head);
  const req = new Uint8Array(h.length + (body?.length ?? 0));
  req.set(h);
  if (body) req.set(body, h.length);
  const w = s.writable.getWriter();
  if (chunk > 0) {
    for (let off = 0; off < req.length; off += chunk) await w.write(req.subarray(off, off + chunk));
  } else {
    await w.write(req);
  }
  w.releaseLock();
  await s.closeWrite();
  const written = performance.now() - t;
  const rd = s.readable.getReader();
  let n = 0;
  let ttfb = 0;
  let first: Uint8Array | null = null;
  for (;;) {
    const { value, done } = await rd.read();
    if (done) break;
    if (!first) {
      first = value;
      ttfb = performance.now() - t;
    }
    n += value.length;
  }
  const status = first ? new TextDecoder().decode(first.subarray(0, 12)) : "";
  return { written, ttfb, done: performance.now() - t, bytes: n, status };
}

function claimBody() {
  const ids: string[] = [];
  for (let i = 0; i < 2; i++) {
    const b = crypto.getRandomValues(new Uint8Array(16));
    ids.push('"' + Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("") + '"');
  }
  return enc.encode(`{"surb_ids":[${ids.join(",")}],"encoding":"binary","retain":true}`);
}

async function series(addr: string, o: Opts, call: (conn: any) => Promise<any>) {
  // A dial can fail under emulated loss; retry so the run still measures calls.
  let conn: any = null;
  let dialMs = 0;
  const dialErrors: string[] = [];
  for (let attempt = 0; attempt < 3 && !conn; attempt++) {
    const t = performance.now();
    try {
      conn = await dial(addr, { signal: AbortSignal.timeout(20000) });
      dialMs = performance.now() - t;
    } catch (e: any) {
      dialErrors.push(String(e?.message ?? e));
    }
  }
  if (!conn) return { dialMs, dialErrors, calls: [] };
  const calls = [];
  for (let i = 0; i < o.calls; i++) {
    if (i > 0 && o.gapMs > 0) await sleep(o.gapMs);
    try {
      calls.push(await call(conn));
    } catch (e: any) {
      calls.push({ err: String(e?.message ?? e) });
    }
  }
  await conn.close();
  return { dialMs, dialErrors, calls };
}

const KB = {
  // Claims answered with the mock's reply body: the reply download.
  download(addr: string, o: Opts) {
    return series(addr, o, (conn) => exchange(conn, addr, "POST", "/api/v1/responses/claim", claimBody(), o.chunk));
  },
  // Sphinx-packet-sized POSTs answered with 202: the request upload.
  upload(addr: string, o: Opts) {
    const body = new Uint8Array(o.bytes).fill(0x61);
    return series(addr, o, (conn) => exchange(conn, addr, "POST", "/api/v1/packets", body, o.chunk));
  },
  // Repeated dials, each followed by one GET /health.
  async dial(addr: string, o: Opts) {
    const calls = [];
    for (let i = 0; i < o.calls; i++) {
      const t = performance.now();
      try {
        const conn: any = await dial(addr, { signal: AbortSignal.timeout(20000) });
        const dialMs = performance.now() - t;
        const first = await exchange(conn, addr, "GET", "/health", null, 0);
        calls.push({ dialMs, done: dialMs + first.done });
        await conn.close();
      } catch (e: any) {
        calls.push({ err: String(e?.message ?? e) });
      }
      await sleep(Math.max(o.gapMs, 200));
    }
    return { dialMs: 0, calls };
  },
};
(globalThis as any).KB = KB;
