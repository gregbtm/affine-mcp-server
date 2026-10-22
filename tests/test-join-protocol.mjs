// joinWorkspace must work against AFFiNE >= 0.27.5 (space:join-batch only) and
// <= 0.27.4 (space:join only). Fake sockets mirror each gateway: an event with
// no handler is simply never acknowledged.
import assert from "node:assert/strict";
import { joinWorkspace, loadDoc, pushDocUpdate, serverUsesBatchSync, resetSyncProtocolForTests } from "../dist/ws.js";

process.env.AFFINE_WS_ACK_TIMEOUT_MS ||= "1000";

function fakeSocket(handlers) {
  const seen = [];
  return {
    seen,
    emit(event, payload, ack) {
      seen.push({ event, payload });
      const handler = handlers[event];
      if (handler) setImmediate(() => ack(handler(payload)));
    },
  };
}

function versionAtLeast(v, [maj, min, pat]) {
  const [a, b, c] = String(v).split(/[.-]/).map((n) => Number(n) || 0);
  return a > maj || (a === maj && (b > min || (b === min && c >= pat)));
}

// canary / 0.27.5+
resetSyncProtocolForTests();
const canary = fakeSocket({
  "space:join-batch": (p) => ({ data: { clientId: "c", success: p.spaces.length > 0 && versionAtLeast(p.clientVersion, [0, 27, 5]) } }),
});
await joinWorkspace(canary, "ws-1");
assert.equal(canary.seen[0].event, "space:join-batch");
assert.equal(canary.seen.some((e) => e.event === "space:join"), false, "must not use the removed event");
assert.equal(serverUsesBatchSync(), true);

// stable / 0.27.4: join-batch is unknown, so only the legacy event answers
resetSyncProtocolForTests();
const stable = fakeSocket({ "space:join": () => ({ data: { success: true } }) });
await joinWorkspace(stable, "ws-1");
assert.deepEqual(stable.seen.map((e) => e.event), ["space:join-batch", "space:join"]);
assert.equal(serverUsesBatchSync(), false);
const again = fakeSocket({ "space:join": () => ({ data: { success: true } }) });
await joinWorkspace(again, "ws-1");
assert.deepEqual(again.seen.map((e) => e.event), ["space:join"], "a legacy server is remembered; no repeated probe");

// a server that answers join-batch with an error must surface it, not fall back
resetSyncProtocolForTests();
const denied = fakeSocket({ "space:join-batch": () => ({ error: { message: "Workspace.Sync denied" } }) });
await assert.rejects(() => joinWorkspace(denied, "ws-1"), /Workspace\.Sync denied/);
assert.deepEqual(denied.seen.map((e) => e.event), ["space:join-batch"]);

// a server that rejects the client version must say how to fix it
resetSyncProtocolForTests();
const old = fakeSocket({ "space:join-batch": () => ({ data: { clientId: "c", success: false } }) });
await assert.rejects(() => joinWorkspace(old, "ws-1"), /AFFINE_WS_BATCH_CLIENT_VERSION/);

// 0.27.5+ keeps a per-doc subscription: load-doc / push-doc-update fail with
// "You should join in Space..." until the socket joined that doc (join-batch with docId).
resetSyncProtocolForTests();
const subs = new Set();
const strict = fakeSocket({
  "space:join-batch": (p) => {
    for (const sp of p.spaces) if (sp.docId) subs.add(`${sp.spaceId}/${sp.docId}`);
    return { data: { clientId: "c", success: true } };
  },
  "space:load-doc": (p) => subs.has(`${p.spaceId}/${p.docId}`)
    ? { data: { missing: "AA==", state: "AA==", timestamp: 1 } }
    : { error: { name: "NOT_IN_SPACE", message: `You should join in Space ${p.spaceId} before broadcasting messages.` } },
  "space:push-doc-update": (p) => subs.has(`${p.spaceId}/${p.docId}`)
    ? { data: { accepted: true, timestamp: 5 } }
    : { error: { name: "NOT_IN_SPACE", message: `You should join in Space ${p.spaceId} before broadcasting messages.` } },
});
await joinWorkspace(strict, "ws-1");
const loaded = await loadDoc(strict, "ws-1", "docA");
assert.equal(loaded.timestamp, 1, "loadDoc must join the doc first");
await pushDocUpdate(strict, "ws-1", "docA", "AAA=");
await loadDoc(strict, "ws-1", "docA");
const docJoins = strict.seen.filter((e) => e.event === "space:join-batch" && e.payload.spaces.some((x) => x.docId));
assert.equal(docJoins.length, 1, "each doc is joined once per socket");
await loadDoc(strict, "ws-1", "ws-1");
assert.equal(strict.seen.filter((e) => e.event === "space:join-batch" && e.payload.spaces.some((x) => x.docId)).length, 2);

// a legacy server has no per-doc join step and must never be sent one
resetSyncProtocolForTests();
const legacy = fakeSocket({
  "space:join": () => ({ data: { success: true } }),
  "space:load-doc": () => ({ data: { missing: "AA==", state: "AA==", timestamp: 1 } }),
});
await joinWorkspace(legacy, "ws-1");
await loadDoc(legacy, "ws-1", "docA");
assert.equal(legacy.seen.filter((e) => e.event === "space:join-batch" && e.payload.spaces.some((x) => x.docId)).length, 0);

console.log("Join protocol tests passed");
