// Compatibility workload for a local mesh, run with a published client release.
//
// Sends echo, eth_blockNumber and HTTP requests through every entry x exit pair
// of the mesh described by MESH_INFO, and fails unless every request succeeds
// and every reply delivered to the client carries an identifier the client
// parses for its SURB ID. Trial decryptions (the client's fallback for replies
// it cannot match by ID, also used for late FEC fragments) are reported.
//
// Env:
//   MESH_INFO      path to mesh_info.json written by nox_mesh_server
//   HTTP_PORT      port for the local HTTP origin (default 18080)
//   ECHO_PER_PAIR  echo requests per entry x exit pair (default 2)
//   RPC_PER_PAIR   eth_blockNumber calls per entry x exit pair (default 2)
//   LARGE_BYTES    size of the large HTTP response (default 1048576)
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { NoxClient, encodeServiceRequest } from "@hisoka-io/nox-client";

const mesh = JSON.parse(readFileSync(process.env.MESH_INFO, "utf8"));
const HTTP_PORT = Number(process.env.HTTP_PORT ?? 18080);
const ECHO_PER_PAIR = Number(process.env.ECHO_PER_PAIR ?? 2);
const RPC_PER_PAIR = Number(process.env.RPC_PER_PAIR ?? 2);
const LARGE_BYTES = Number(process.env.LARGE_BYTES ?? 1024 * 1024);
const CALL_TIMEOUT_MS = 120_000;

const t0 = Date.now();
const log = (...a) => console.log(`[${((Date.now() - t0) / 1000).toFixed(1)}s]`, ...a);

const small = Buffer.alloc(1024, 0x61);
const large = Buffer.alloc(LARGE_BYTES);
for (let i = 0; i < large.length; i++) large[i] = i % 251;
const origin = createServer((req, res) => {
  const body = req.url === "/large" ? large : small;
  res.writeHead(200, { "content-type": "application/octet-stream", "content-length": body.length });
  res.end(body);
});
await new Promise((r) => origin.listen(HTTP_PORT, "127.0.0.1", r));

function withTimeout(p, ms, what) {
  let timer;
  return Promise.race([
    p.finally(() => clearTimeout(timer)),
    new Promise((_, rej) => {
      timer = setTimeout(() => rej(new Error(`${what} timed out after ${ms}ms`)), ms);
    }),
  ]);
}

const entries = mesh.nodes.map((n) => `http://127.0.0.1:${n.ingress_port}`);
const exitIds = mesh.nodes.filter((n) => n.role === 2 || n.role === 3).map((n) => n.id);
const seed = `http://127.0.0.1:${mesh.nodes[0].metrics_port}`;
const results = [];
let trialDecryptions = 0;
// Replies whose SURB ID is registered but which do not decrypt with it.
let decryptByIdFailures = 0;
// Replies for SURBs the client already released (late FEC fragments, retries).
let lateReplies = 0;
const replyIdShapes = {};
let unparsedReplyIds = 0;

// Every reply ID the entry hands out, over HTTP claim or WebSocket.
function recordReplyId(id) {
  const shape = String(id).replace(/[0-9a-f]{32}$/, "{surb}").replace(/-\d+-/, "-N-");
  replyIdShapes[shape] = (replyIdShapes[shape] ?? 0) + 1;
  if (!/^[a-z]+-\d+-[0-9a-f]{32}$/.test(String(id))) unparsedReplyIds++;
}
const realFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const resp = await realFetch(input, init);
  if (String(input).endsWith("/api/v1/responses/claim") && resp.status === 200) {
    try {
      for (const item of await resp.clone().json()) recordReplyId(item.id);
    } catch {}
  }
  return resp;
};

async function connect() {
  const client = await withTimeout(
    NoxClient.connect({
      seeds: [seed],
      powDifficulty: 0,
      timeoutMs: CALL_TIMEOUT_MS,
      dangerouslySkipFingerprintCheck: true,
    }),
    60_000,
    "connect",
  );
  const onWs = client._onWsResponse.bind(client);
  client._onWsResponse = (item) => {
    recordReplyId(item.id);
    return onWs(item);
  };
  const pool = client.surbPool;
  const byId = pool.decryptById.bind(pool);
  pool.decryptById = (wasm, idHex, body) => {
    const known = pool.registry.has(idHex);
    const out = byId(wasm, idHex, body);
    if (out === null) {
      if (known) decryptByIdFailures++;
      else lateReplies++;
    }
    return out;
  };
  const match = pool.matchAndDecrypt.bind(pool);
  pool.matchAndDecrypt = (...args) => {
    trialDecryptions++;
    return match(...args);
  };
  return client;
}

async function useEntry(client, entryUrl) {
  if (client._entryUrl === entryUrl) return;
  client.responseWs?.close?.();
  if (client.stallTimer) clearInterval(client.stallTimer);
  if (client.pollTimer) clearInterval(client.pollTimer);
  client._entryUrl = entryUrl;
  client.subscribedSurbIds?.clear?.();
  client._startResponseStream();
  await new Promise((r) => setTimeout(r, 1000));
}

async function run(kind, entry, exitId, fn, check) {
  const st = Date.now();
  try {
    const out = await withTimeout(fn(), CALL_TIMEOUT_MS, kind);
    const err = check(out);
    results.push({ kind, entry, exitId, ok: err === null, ms: Date.now() - st, err });
  } catch (e) {
    results.push({ kind, entry, exitId, ok: false, ms: Date.now() - st, err: String(e.message ?? e).slice(0, 160) });
  }
  const r = results[results.length - 1];
  if (!r.ok) log(`FAIL ${kind} ${entry} -> exit ${exitId}: ${r.err}`);
}

const client = await connect();
const nodes = client._nodes;
const orig = client._sendAnonymous.bind(client);
const dec = new TextDecoder();

for (const entryUrl of entries) {
  await useEntry(client, entryUrl);
  for (const exitId of exitIds) {
    const exitUrl = `http://127.0.0.1:${mesh.nodes[exitId].ingress_port}`;
    const exitNode = nodes.find((n) => n.address === exitUrl);
    if (exitUrl === entryUrl) continue; // the client never uses one node as both
    if (!exitNode) {
      results.push({ kind: "route", entry: entryUrl, exitId, ok: false, err: "exit not in topology" });
      continue;
    }
    client._sendAnonymous = (inner, opKey, t, e, s, sel) => orig(inner, opKey, t, e, s, sel ?? exitNode);

    for (let i = 0; i < ECHO_PER_PAIR; i++) {
      const data = new TextEncoder().encode(`echo-${exitId}-${i}`);
      await run(
        "echo",
        entryUrl,
        exitId,
        () => client._sendAnonymous(encodeServiceRequest({ tag: "Echo", data }), "echo"),
        (out) => (dec.decode(out) === dec.decode(data) ? null : "echo mismatch"),
      );
    }
    for (let i = 0; i < RPC_PER_PAIR; i++) {
      await run(
        "rpc",
        entryUrl,
        exitId,
        () => client.rpcCall("eth_blockNumber", []),
        (out) => (/^0x[0-9a-f]+$/.test(out) ? null : `bad block number ${out}`),
      );
    }
    await run(
      "http-1k",
      entryUrl,
      exitId,
      () => client.httpRequest("GET", `http://127.0.0.1:${HTTP_PORT}/small`, [], new Uint8Array()),
      (out) => (out.length > small.length ? null : `short response ${out.length}`),
    );
  }
}

// Large responses need several reply rounds; one per exit through the first entry.
await useEntry(client, entries[0]);
for (const exitId of exitIds) {
  if (mesh.nodes[exitId].ingress_port === mesh.nodes[0].ingress_port) continue;
  const exitUrl = `http://127.0.0.1:${mesh.nodes[exitId].ingress_port}`;
  const exitNode = nodes.find((n) => n.address === exitUrl);
  client._sendAnonymous = (inner, opKey, t, e, s, sel) => orig(inner, opKey, t, e, s, sel ?? exitNode);
  await run(
    "http-large",
    entries[0],
    exitId,
    () => client.httpRequest("GET", `http://127.0.0.1:${HTTP_PORT}/large`, [], new Uint8Array(), { timeoutMs: CALL_TIMEOUT_MS }),
    (out) => (out.length > large.length ? null : `short response ${out.length}`),
  );
}

try { client.disconnect(); } catch {}
origin.close();

const byKind = {};
for (const r of results) {
  byKind[r.kind] ??= { ok: 0, total: 0, ms: [] };
  byKind[r.kind].total++;
  if (r.ok) { byKind[r.kind].ok++; byKind[r.kind].ms.push(r.ms); }
}
for (const [kind, s] of Object.entries(byKind)) {
  s.ms.sort((a, b) => a - b);
  const p = (q) => s.ms.length ? s.ms[Math.min(s.ms.length - 1, Math.floor(q * s.ms.length))] : 0;
  log(`${kind}: ${s.ok}/${s.total} ok, p50 ${p(0.5)}ms, p95 ${p(0.95)}ms`);
}
log(`reply identifiers seen: ${JSON.stringify(replyIdShapes)}`);
const ok = results.filter((r) => r.ok).length;
const pass =
  ok === results.length && results.length > 0 && unparsedReplyIds === 0 && decryptByIdFailures === 0;
log(
  `SUMMARY ${ok}/${results.length} ok, unparsed reply ids ${unparsedReplyIds}, ` +
    `failed decryptions by id ${decryptByIdFailures}, late replies ${lateReplies}, ` +
    `trial decryptions ${trialDecryptions} => ${pass ? "PASS" : "FAIL"}`,
);
process.exit(pass ? 0 : 1);
