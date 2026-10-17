#!/usr/bin/env node
/**
 * Validates every GraphQL document in src/tools/accessAdmin.ts against a vendored
 * copy of AFFiNE's schema.gql, then exercises the tools' safety rules through a
 * real MCP client/server pair with a stub GraphQL client.
 *
 * A validator that accepts everything would also pass, so the first assertions
 * prove it can fail: a deliberately wrong document must be rejected.
 */
import "./require-destructive-test-safety.mjs";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { buildSchema, parse, validate } from "graphql";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { OPERATIONS, graphqlDocumentWrites, registerAccessAdminTools } from "../src/tools/accessAdmin.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const schema = buildSchema(readFileSync(path.join(here, "fixtures", "affine-schema.gql"), "utf8"));

const problems = (source) => validate(schema, parse(source)).map((e) => e.message);

// --- negative controls: the validator must be able to say no ---------------
assert.ok(problems("query { noSuchRootField }").length > 0, "unknown field must be rejected");
assert.ok(problems("mutation($i:Int){ deleteUser(id:$i){ success } }").length > 0, "wrong variable type must be rejected");
assert.ok(problems("mutation($id:ID!,$w:ID!){ revokeMcpCredential(workspaceId:$w,id:$id) }").length > 0, "ID! where String! is required must be rejected");

// --- every shipped document must be valid ----------------------------------
const entries = Object.entries(OPERATIONS);
assert.ok(entries.length >= 30, `expected the operation table to be populated, got ${entries.length}`);
const failures = entries.flatMap(([name, source]) => problems(source).map((m) => `${name}: ${m}`));
assert.deepEqual(failures, [], `GraphQL documents invalid against AFFiNE schema:\n${failures.join("\n")}`);

// --- mutation detection ------------------------------------------------------
assert.equal(graphqlDocumentWrites("{ currentUser { id } }"), false);
assert.equal(graphqlDocumentWrites("query Q { workspaces { id } }"), false);
assert.equal(graphqlDocumentWrites("mutation { deleteWorkspace(id:\"x\") }"), true);
assert.equal(graphqlDocumentWrites("  MUTATION" .toLowerCase() + " M { a }"), true);
assert.equal(graphqlDocumentWrites("subscription S { a }"), true);
assert.equal(graphqlDocumentWrites('query { search(input:{keyword:"mutation"}) { id } }'), false, "keyword inside a string is not an operation");
assert.equal(graphqlDocumentWrites("# mutation\nquery { a }"), false, "keyword inside a comment is not an operation");
assert.equal(graphqlDocumentWrites('query { a(s:"""x\nmutation"""){ id } } mutation { b }'), true, "a real mutation after a block string is still caught");

// --- behaviour through an MCP client ------------------------------------------
const calls = [];
const gql = {
  request: async (query, variables) => {
    calls.push({ query, variables });
    return {
      deleteUser: { success: true },
      revokeMember: true,
      revokeMcpCredential: true,
      deleteReply: true,
      updateAppConfig: { ok: 1 },
      banUser: { id: "u", email: "e", disabled: true },
      __schema: { queryType: { name: "Query" } },
    };
  },
};
const server = new McpServer({ name: "t", version: "0" });
registerAccessAdminTools(server, gql, { workspaceId: "ws-default" });
const client = new Client({ name: "t-client", version: "0" });
const [ct, st] = InMemoryTransport.createLinkedPair();
await Promise.all([server.connect(st), client.connect(ct)]);

const call = async (name, args) => {
  const r = await client.callTool({ name, arguments: args });
  return { isError: r.isError === true, body: r.structuredContent ?? JSON.parse(r.content[0].text) };
};

const listed = (await client.listTools()).tools.map((t) => t.name);
assert.ok(listed.includes("graphql_execute") && listed.includes("delete_user"), "tools must be advertised");

// Destructive tools refuse without a matching confirmation and make NO request.
for (const [tool, args] of [
  ["delete_user", { userId: "u1", confirmUserId: "other" }],
  ["remove_member", { userId: "u1", confirmUserId: "nope" }],
  ["revoke_mcp_credential", { credentialId: "c1", confirmCredentialId: "x" }],
  ["delete_reply", { replyId: "r1", confirmReplyId: "x" }],
  ["update_app_config", { module: "m", key: "k", value: 1, confirmKey: "m.wrong" }],
  ["set_user_disabled", { userId: "u1", disabled: true }],
]) {
  const before = calls.length;
  const r = await call(tool, args);
  assert.equal(r.isError, true, `${tool} must refuse without a valid confirmation`);
  assert.equal(calls.length, before, `${tool} must not reach AFFiNE when refused`);
}

// With the right confirmation they go through, using the default workspace.
let r = await call("remove_member", { userId: "u1", confirmUserId: "u1" });
assert.equal(r.isError, false);
assert.equal(calls.at(-1).variables.workspaceId, "ws-default");
r = await call("update_app_config", { module: "m", key: "k", value: 1, confirmKey: "m.k" });
assert.deepEqual(calls.at(-1).variables.updates, [{ module: "m", key: "k", value: 1 }]);

// Raw GraphQL: queries free, mutations gated.
const before = calls.length;
r = await call("graphql_execute", { query: "mutation { deleteWorkspace(id:\"x\") }" });
assert.equal(r.isError, true, "mutation without allowMutation must be refused");
assert.equal(calls.length, before, "refused mutation must not be sent");
r = await call("graphql_execute", { query: "{ __schema { queryType { name } } }" });
assert.equal(r.isError, false);
assert.equal(calls.length, before + 1);
r = await call("graphql_execute", { query: "mutation { x }", allowMutation: true });
assert.equal(r.isError, false);
assert.equal(calls.length, before + 2);

// A tool with no workspace and no default fails clearly.
const bare = new McpServer({ name: "t2", version: "0" });
registerAccessAdminTools(bare, gql, {});
const c2 = new Client({ name: "c2", version: "0" });
const [ct2, st2] = InMemoryTransport.createLinkedPair();
await Promise.all([bare.connect(st2), c2.connect(ct2)]);
const nr = await c2.callTool({ name: "list_workspace_members", arguments: {} });
assert.equal(nr.isError, true);

console.log(`graphql operations ok: ${entries.length} documents validated, safety rules enforced`);
await client.close();
await c2.close();
