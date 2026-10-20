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
import { redactConfig, REDACTED } from "../src/util/redactConfig.ts";

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

// --- get_app_config: stable 0.27.4 compatibility and secret redaction ----------
// The stable image has no appConfigMetadata, and returns secrets unmasked.
assert.ok(!OPERATIONS.getAppConfig.includes("appConfigMetadata"), "the default document must not name a field stable lacks");
const stableSchema = buildSchema(readFileSync(path.join(here, "fixtures", "affine-schema.gql"), "utf8").replace(/\n\s*appConfigMetadata[^\n]*/g, ""));
assert.ok(validate(stableSchema, parse(OPERATIONS.getAppConfig)).length === 0, "default document must validate against a schema without appConfigMetadata");
assert.ok(validate(stableSchema, parse(OPERATIONS.getAppConfigMetadata)).length > 0, "negative control: the metadata document is rejected by a schema without the field");

const SECRET_CONFIG = {
  crypto: { privateKey: "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n" },
  mailer: { SMTP: { host: "smtp.example.com", port: 465, username: "u@example.com", password: "smtp-pass-123", sender: "u@example.com" }, fallbackSMTP: { password: "" } },
  db: { datasourceUrl: "postgresql://affine:db-pass-456@postgres:5432/affine" },
  oauth: { providers: { google: { clientId: "id", clientSecret: "oauth-secret-789" } } },
  copilot: { exa: { key: "exa-key-000" } },
  auth: { token: { accessTokenTtl: 900 }, passwordRequirements: { min: 8, max: 32 } },
  server: { externalUrl: "https://affine.example.com", port: 3010 },
};
const redacted = redactConfig(SECRET_CONFIG);
const dump = JSON.stringify(redacted);
for (const leaked of ["smtp-pass-123", "db-pass-456", "oauth-secret-789", "exa-key-000", "BEGIN EC PRIVATE KEY", "AAAA"]) {
  assert.ok(!dump.includes(leaked), `redaction must remove ${leaked}`);
}
assert.equal(redacted.mailer.SMTP.password, REDACTED);
assert.equal(redacted.mailer.fallbackSMTP.password, "", "an unset secret stays empty so 'not configured' is visible");
assert.equal(redacted.db.datasourceUrl, `postgresql://affine:${REDACTED}@postgres:5432/affine`);
assert.equal(redacted.mailer.SMTP.host, "smtp.example.com", "non-secret values are untouched");
assert.equal(redacted.auth.token.accessTokenTtl, 900, "numbers under token-like parents are untouched");
assert.deepEqual(redacted.auth.passwordRequirements, { min: 8, max: 32 }, "passwordRequirements numbers are untouched");
assert.equal(SECRET_CONFIG.mailer.SMTP.password, "smtp-pass-123", "redaction must not mutate its input");

const stableGql = {
  request: async (query) => {
    if (query.includes("appConfigMetadata")) throw new Error('GraphQL HTTP 400: Cannot query field "appConfigMetadata" on type "Query".');
    return { appConfig: SECRET_CONFIG };
  },
};
const cfgServer = new McpServer({ name: "t3", version: "0" });
registerAccessAdminTools(cfgServer, stableGql, {});
const c3 = new Client({ name: "c3", version: "0" });
const [ct3, st3] = InMemoryTransport.createLinkedPair();
await Promise.all([cfgServer.connect(st3), c3.connect(ct3)]);
const parse3 = (res) => res.structuredContent ?? JSON.parse(res.content[0].text);

let cfg = await c3.callTool({ name: "get_app_config", arguments: {} });
assert.equal(cfg.isError ?? false, false, "get_app_config must work on a server without appConfigMetadata");
assert.ok(!JSON.stringify(parse3(cfg)).includes("smtp-pass-123"), "get_app_config must not return secrets");
cfg = await c3.callTool({ name: "get_app_config", arguments: { includeMetadata: true } });
assert.equal(cfg.isError ?? false, false, "includeMetadata must degrade, not fail, when the field is missing");
assert.equal(parse3(cfg).metadata, null);
assert.match(parse3(cfg).metadataUnavailable, /appConfigMetadata/);

// Any other failure while fetching metadata is still surfaced.
const brokenGql = { request: async (q) => { if (q.includes("appConfigMetadata")) throw new Error("boom"); return { appConfig: {} }; } };
const brokenServer = new McpServer({ name: "t4", version: "0" });
registerAccessAdminTools(brokenServer, brokenGql, {});
const c4 = new Client({ name: "c4", version: "0" });
const [ct4, st4] = InMemoryTransport.createLinkedPair();
await Promise.all([brokenServer.connect(st4), c4.connect(ct4)]);
assert.equal((await c4.callTool({ name: "get_app_config", arguments: { includeMetadata: true } })).isError, true, "unrelated metadata errors must not be swallowed");

console.log(`graphql operations ok: ${entries.length} documents validated, safety rules enforced`);
await client.close();
await c2.close();
await c3.close();
await c4.close();
