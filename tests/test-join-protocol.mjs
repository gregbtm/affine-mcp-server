// joinWorkspace must work against AFFiNE >= 0.27.5 (space:join-batch only) and
// <= 0.27.4 (space:join only). Fake sockets mirror each gateway: an event with
// no handler is simply never acknowledged.
import assert from "node:assert/strict";
import { joinWorkspace, serverUsesBatchSync, resetSyncProtocolForTests } from "../dist/ws.js";

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

console.log("Join protocol tests passed");
