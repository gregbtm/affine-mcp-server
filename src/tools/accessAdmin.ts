import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { GraphQLClient } from "../graphqlClient.js";
import { text, toolError } from "../util/mcp.js";
import { normalizeCommentContent } from "../util/commentContent.js";
import { BoundedOffset, BoundedPageSize, requireMatchingConfirmation } from "../util/inputSchemas.js";
import { redactConfig } from "../util/redactConfig.js";

/**
 * Typed wrappers for AFFiNE GraphQL operations the rest of this server does not
 * reach: workspace membership and invites, per-doc roles, comment replies, MCP
 * credentials, embedding ignore-lists, server administration, plus a guarded
 * raw GraphQL escape hatch. Every operation document below is validated against
 * AFFiNE's schema.gql by tests/test-graphql-operations.mjs.
 *
 * Tool names must stay string literals passed straight to server.registerTool: the manifest check
 * (scripts/verify-tool-manifest.mjs) finds tools by regex, not by running code.
 */
export type AccessAdminDefaults = { workspaceId?: string };

type Wrapped<A> = (args: A) => Promise<ReturnType<typeof text> | ReturnType<typeof toolError>>;

const WorkspaceIdArg = z.string().optional().describe("AFFiNE workspace id. Omit only when AFFINE_WORKSPACE_ID is configured.");
const DocRoleArg = z.enum(["Reader", "Commenter", "Editor", "Manager", "Owner", "External", "None"]);
const PageSize = BoundedPageSize.optional();
const Offset = BoundedOffset.optional();

/** Every operation document in this module, exported so the schema test can validate them. */
export const OPERATIONS = {
  listMembers: `query ListWorkspaceMembers($workspaceId:String!,$query:String,$skip:Int,$take:Int){ workspace(id:$workspaceId){ memberCount members(query:$query,skip:$skip,take:$take){ id name email avatarUrl role status inviteId } } }`,
  inviteMembers: `mutation InviteMembers($workspaceId:String!,$emails:[String!]!){ inviteMembers(workspaceId:$workspaceId,emails:$emails){ email inviteId error } }`,
  approveMember: `mutation ApproveMember($workspaceId:String!,$userId:String!){ approveMember(workspaceId:$workspaceId,userId:$userId) }`,
  grantMember: `mutation GrantMember($workspaceId:String!,$userId:String!,$permission:Permission!){ grantMember(workspaceId:$workspaceId,userId:$userId,permission:$permission) }`,
  revokeMember: `mutation RevokeMember($workspaceId:String!,$userId:String!){ revokeMember(workspaceId:$workspaceId,userId:$userId) }`,
  getInviteLink: `query GetInviteLink($workspaceId:String!){ workspace(id:$workspaceId){ inviteLink{ link expireTime } } }`,
  createInviteLink: `mutation CreateInviteLink($workspaceId:String!,$expireTime:WorkspaceInviteLinkExpireTime!){ createInviteLink(workspaceId:$workspaceId,expireTime:$expireTime){ link expireTime } }`,
  revokeInviteLink: `mutation RevokeInviteLink($workspaceId:String!){ revokeInviteLink(workspaceId:$workspaceId) }`,
  listDocRoles: `query ListDocRoles($workspaceId:String!,$docId:String!,$first:Int,$offset:Int){ workspace(id:$workspaceId){ doc(docId:$docId){ id defaultRole public grantedUsersList(pagination:{first:$first,offset:$offset}){ totalCount pageInfo{ hasNextPage endCursor } edges{ node{ role user{ id name email } } } } } } }`,
  grantDocRoles: `mutation GrantDocUserRoles($input:GrantDocUserRolesInput!){ grantDocUserRoles(input:$input) }`,
  updateDocUserRole: `mutation UpdateDocUserRole($input:UpdateDocUserRoleInput!){ updateDocUserRole(input:$input) }`,
  revokeDocUserRole: `mutation RevokeDocUserRoles($input:RevokeDocUserRoleInput!){ revokeDocUserRoles(input:$input) }`,
  updateDocDefaultRole: `mutation UpdateDocDefaultRole($input:UpdateDocDefaultRoleInput!){ updateDocDefaultRole(input:$input) }`,
  createReply: `mutation CreateReply($input:ReplyCreateInput!){ createReply(input:$input){ id commentId content createdAt updatedAt user{ id name } } }`,
  updateReply: `mutation UpdateReply($input:ReplyUpdateInput!){ updateReply(input:$input) }`,
  deleteReply: `mutation DeleteReply($id:String!){ deleteReply(id:$id) }`,
  listMcpCredentials: `query ListMcpCredentials($workspaceId:String!){ mcpCredentials(workspaceId:$workspaceId){ id name accessMode status fingerprint createdAt expiresAt lastUsedAt revokedAt graceEndsAt workspaceId } }`,
  createMcpCredential: `mutation CreateMcpCredential($input:CreateMcpCredentialInput!){ createMcpCredential(input:$input){ token credential{ id name accessMode status fingerprint expiresAt workspaceId } } }`,
  rotateMcpCredential: `mutation RotateMcpCredential($workspaceId:String!,$id:ID!,$expirationDays:Int!){ rotateMcpCredential(workspaceId:$workspaceId,id:$id,expirationDays:$expirationDays){ token credential{ id name accessMode status fingerprint expiresAt graceEndsAt workspaceId } } }`,
  revokeMcpCredential: `mutation RevokeMcpCredential($workspaceId:String!,$id:ID!){ revokeMcpCredential(workspaceId:$workspaceId,id:$id) }`,
  embeddingIgnoredDocs: `mutation UpdateEmbeddingIgnoredDocs($workspaceId:String!,$add:[String!],$remove:[String!]){ updateWorkspaceEmbeddingIgnoredDocs(workspaceId:$workspaceId,add:$add,remove:$remove) }`,
  adminDashboard: `query AdminDashboard($input:AdminDashboardInput){ adminDashboard(input:$input){ syncActiveUsers copilotConversations workspaceStorageBytes blobStorageBytes generatedAt topSharedLinks{ __typename } } }`,
  adminWorkspaces: `query AdminWorkspaces($filter:ListWorkspaceInput!){ adminWorkspacesCount(filter:$filter) adminWorkspaces(filter:$filter){ id name createdAt memberCount publicPageCount snapshotCount snapshotSize blobCount blobSize public enableAi enableSharing enableUrlPreview enableDocEmbedding owner{ id name email } } }`,
  adminWorkspace: `query AdminWorkspace($id:String!,$take:Int){ adminWorkspace(id:$id){ id name createdAt memberCount publicPageCount snapshotCount snapshotSize blobCount blobSize public enableAi enableSharing enableUrlPreview enableDocEmbedding owner{ id name email } members(take:$take){ id name email role status } sharedLinks{ __typename } } }`,
  listUsers: `query ListUsers($filter:ListUserInput!){ usersCount(filter:$filter) users(filter:$filter){ id name email disabled emailVerified hasPassword features } }`,
  getUser: `query GetUser($email:String!){ userByEmail(email:$email){ id name email disabled emailVerified hasPassword features } }`,
  createUser: `mutation CreateUser($input:CreateUserInput!){ createUser(input:$input){ id name email } }`,
  updateUser: `mutation UpdateUser($id:String!,$input:ManageUserInput!){ updateUser(id:$id,input:$input){ id name email disabled } }`,
  banUser: `mutation BanUser($id:String!){ banUser(id:$id){ id email disabled } }`,
  enableUser: `mutation EnableUser($id:String!){ enableUser(id:$id){ id email disabled } }`,
  deleteUser: `mutation DeleteUser($id:String!){ deleteUser(id:$id){ success } }`,
  // appConfigMetadata only exists on newer AFFiNE builds (canary 0.27.5); the stable 0.27.4 image rejects
  // any document that names it, so it is fetched separately and its absence is tolerated.
  getAppConfig: `query GetAppConfig{ appConfig }`,
  getAppConfigMetadata: `query GetAppConfigMetadata{ appConfigMetadata }`,
  validateAppConfig: `query ValidateAppConfig($updates:[UpdateAppConfigInput!]!){ validateAppConfig(updates:$updates){ module key valid error value } }`,
  updateAppConfig: `mutation UpdateAppConfig($updates:[UpdateAppConfigInput!]!){ updateAppConfig(updates:$updates) }`,
} as const;

/** Strip string literals and comments so keyword detection cannot be fooled by them. */
export function stripGraphqlNoise(source: string): string {
  return source
    .replace(/"""[\s\S]*?"""/g, '""')
    .replace(/"(?:\\.|[^"\\])*"/g, '""')
    .replace(/#[^\n\r]*/g, "");
}

/** True when the document declares any operation that is not a plain query. */
export function graphqlDocumentWrites(source: string): boolean {
  return /\b(mutation|subscription)\b/.test(stripGraphqlNoise(source));
}

export function registerAccessAdminTools(server: McpServer, gql: GraphQLClient, defaults: AccessAdminDefaults) {
  const wsId = (given?: string): string => {
    const id = given || defaults.workspaceId;
    if (!id) throw new Error("workspaceId required (or set AFFINE_WORKSPACE_ID)");
    return id;
  };
  const wrap = <A>(code: string, fn: (args: A) => Promise<Record<string, unknown>>): Wrapped<A> =>
    async (args: A) => {
      try {
        return text(await fn(args));
      } catch (error: any) {
        return toolError(error, { code });
      }
    };
  // AFFiNE's admin dashboard and admin workspace resolvers start with
  // `assertCloudOnly()`, which throws NotFoundException on self-hosted servers
  // before the Admin role is checked. The client only sees "Resource not found".
  const cloudOnly = async <T>(request: Promise<T>): Promise<T> => {
    try {
      return await request;
    } catch (error: any) {
      const message = String(error?.message ?? error);
      if (/resource not found/i.test(message)) {
        throw new Error(`${message} AFFiNE's admin dashboard and admin workspace queries are cloud-only: a self-hosted server answers "Resource not found" to them even for an Admin account. Use list_workspaces, list_workspace_members and list_users instead.`);
      }
      throw error;
    }
  };
  const confirmed = (what: string) => z.string().describe(`Must exactly match ${what} to confirm this destructive action.`);
  const done = (ok: boolean, what: string, extra: Record<string, unknown> = {}) => {
    if (!ok) throw new Error(`AFFiNE did not confirm ${what}.`);
    return { ok: true, ...extra };
  };

  // ---------------------------------------------------------------- members
  server.registerTool(
    "list_workspace_members",
    {
      title: "List Workspace Members",
      description: "List members of a workspace with role (Owner/Admin/Collaborator) and status (Accepted/Pending/UnderReview). Use the returned id with set_member_role, approve_member and remove_member.",
      inputSchema: {
        workspaceId: WorkspaceIdArg,
        query: z.string().optional().describe("Filter by name or email."),
        skip: Offset,
        take: PageSize,
      },
    },
    wrap("list_members_failed", async (a: { workspaceId?: string; query?: string; skip?: number; take?: number }) => {
      const data = await gql.request<{ workspace: any }>(OPERATIONS.listMembers, { workspaceId: wsId(a.workspaceId), query: a.query, skip: a.skip, take: a.take });
      return { memberCount: data.workspace.memberCount, items: data.workspace.members };
    }) as any,
  );

  server.registerTool(
    "invite_members",
    {
      title: "Invite Members",
      description: "Invite people to a workspace by email. Sends invitation emails if the server has mail configured. Returns one result per email, with an error object for any that failed.",
      inputSchema: {
        workspaceId: WorkspaceIdArg,
        emails: z.array(z.string().email()).min(1).max(50).describe("Email addresses to invite (max 50)."),
      },
    },
    wrap("invite_members_failed", async (a: { workspaceId?: string; emails: string[] }) => {
      const data = await gql.request<{ inviteMembers: any[] }>(OPERATIONS.inviteMembers, { workspaceId: wsId(a.workspaceId), emails: a.emails });
      return { items: data.inviteMembers };
    }) as any,
  );

  server.registerTool(
    "approve_member",
    {
      title: "Approve Member",
      description: "Approve a member who is waiting for review (status UnderReview), for example after joining through an invite link on a workspace that requires approval.",
      inputSchema: { workspaceId: WorkspaceIdArg, userId: z.string().describe("User id from list_workspace_members.") },
    },
    wrap("approve_member_failed", async (a: { workspaceId?: string; userId: string }) => {
      const data = await gql.request<{ approveMember: boolean }>(OPERATIONS.approveMember, { workspaceId: wsId(a.workspaceId), userId: a.userId });
      return done(data.approveMember, "the member approval", { userId: a.userId });
    }) as any,
  );

  server.registerTool(
    "set_member_role",
    {
      title: "Set Member Role",
      description: "Change a member's workspace role. Owner transfer is not done here; Use Admin or Collaborator.",
      inputSchema: {
        workspaceId: WorkspaceIdArg,
        userId: z.string().describe("User id from list_workspace_members."),
        permission: z.enum(["Admin", "Collaborator"]).describe("New workspace role."),
      },
    },
    wrap("set_member_role_failed", async (a: { workspaceId?: string; userId: string; permission: string }) => {
      const data = await gql.request<{ grantMember: boolean }>(OPERATIONS.grantMember, { workspaceId: wsId(a.workspaceId), userId: a.userId, permission: a.permission });
      return done(data.grantMember, "the role change", { userId: a.userId, permission: a.permission });
    }) as any,
  );

  server.registerTool(
    "remove_member",
    {
      title: "Remove Member",
      description: "Remove a member from a workspace, or cancel a pending invitation. They lose access immediately. Pass confirmUserId equal to userId.",
      inputSchema: {
        workspaceId: WorkspaceIdArg,
        userId: z.string().describe("User id from list_workspace_members."),
        confirmUserId: confirmed("userId"),
      },
    },
    wrap("remove_member_failed", async (a: { workspaceId?: string; userId: string; confirmUserId: string }) => {
      requireMatchingConfirmation("remove_member", a.userId, a.confirmUserId);
      const data = await gql.request<{ revokeMember: boolean }>(OPERATIONS.revokeMember, { workspaceId: wsId(a.workspaceId), userId: a.userId });
      return done(data.revokeMember, "the member removal", { userId: a.userId });
    }) as any,
  );

  server.registerTool(
    "get_invite_link",
    {
      title: "Get Invite Link",
      description: "Return the workspace's current invite link and its expiry, or null if none exists.",
      inputSchema: { workspaceId: WorkspaceIdArg },
    },
    wrap("get_invite_link_failed", async (a: { workspaceId?: string }) => {
      const data = await gql.request<{ workspace: any }>(OPERATIONS.getInviteLink, { workspaceId: wsId(a.workspaceId) });
      return { inviteLink: data.workspace.inviteLink ?? null };
    }) as any,
  );

  server.registerTool(
    "create_invite_link",
    {
      title: "Create Invite Link",
      description: "Create a shareable invite link for the workspace. Anyone with the link can request to join, so treat the returned URL as a credential. Replaces any existing link.",
      inputSchema: {
        workspaceId: WorkspaceIdArg,
        expireTime: z.enum(["OneDay", "ThreeDays", "OneWeek", "OneMonth"]).describe("How long the link stays valid."),
      },
    },
    wrap("create_invite_link_failed", async (a: { workspaceId?: string; expireTime: string }) => {
      const data = await gql.request<{ createInviteLink: any }>(OPERATIONS.createInviteLink, { workspaceId: wsId(a.workspaceId), expireTime: a.expireTime });
      return { inviteLink: data.createInviteLink };
    }) as any,
  );

  server.registerTool(
    "revoke_invite_link",
    {
      title: "Revoke Invite Link",
      description: "Invalidate the workspace's invite link. People who already joined keep access; use remove_member for those.",
      inputSchema: { workspaceId: WorkspaceIdArg },
    },
    wrap("revoke_invite_link_failed", async (a: { workspaceId?: string }) => {
      const data = await gql.request<{ revokeInviteLink: boolean }>(OPERATIONS.revokeInviteLink, { workspaceId: wsId(a.workspaceId) });
      return done(data.revokeInviteLink, "the invite link revocation");
    }) as any,
  );

  // -------------------------------------------------------------- doc roles
  server.registerTool(
    "list_doc_roles",
    {
      title: "List Doc Roles",
      description: "Show who has an explicit role on a document, plus the document's default role (what other workspace members get) and whether it is public.",
      inputSchema: { workspaceId: WorkspaceIdArg, docId: z.string(), first: PageSize, offset: Offset },
    },
    wrap("list_doc_roles_failed", async (a: { workspaceId?: string; docId: string; first?: number; offset?: number }) => {
      const data = await gql.request<{ workspace: any }>(OPERATIONS.listDocRoles, { workspaceId: wsId(a.workspaceId), docId: a.docId, first: a.first, offset: a.offset });
      const doc = data.workspace.doc;
      return { docId: doc.id, defaultRole: doc.defaultRole, public: doc.public, totalCount: doc.grantedUsersList.totalCount, pageInfo: doc.grantedUsersList.pageInfo, items: doc.grantedUsersList.edges.map((e: any) => e.node) };
    }) as any,
  );

  server.registerTool(
    "grant_doc_user_roles",
    {
      title: "Grant Doc User Roles",
      description: "Give one or more users the same role on a document. Users must already be workspace members.",
      inputSchema: { workspaceId: WorkspaceIdArg, docId: z.string(), userIds: z.array(z.string()).min(1).max(100), role: DocRoleArg },
    },
    wrap("grant_doc_roles_failed", async (a: { workspaceId?: string; docId: string; userIds: string[]; role: string }) => {
      const input = { workspaceId: wsId(a.workspaceId), docId: a.docId, userIds: a.userIds, role: a.role };
      const data = await gql.request<{ grantDocUserRoles: boolean }>(OPERATIONS.grantDocRoles, { input });
      return done(data.grantDocUserRoles, "the role grant", { docId: a.docId, userIds: a.userIds, role: a.role });
    }) as any,
  );

  server.registerTool(
    "update_doc_user_role",
    {
      title: "Update Doc User Role",
      description: "Change one user's existing role on a document.",
      inputSchema: { workspaceId: WorkspaceIdArg, docId: z.string(), userId: z.string(), role: DocRoleArg },
    },
    wrap("update_doc_user_role_failed", async (a: { workspaceId?: string; docId: string; userId: string; role: string }) => {
      const input = { workspaceId: wsId(a.workspaceId), docId: a.docId, userId: a.userId, role: a.role };
      const data = await gql.request<{ updateDocUserRole: boolean }>(OPERATIONS.updateDocUserRole, { input });
      return done(data.updateDocUserRole, "the role update", { docId: a.docId, userId: a.userId, role: a.role });
    }) as any,
  );

  server.registerTool(
    "revoke_doc_user_role",
    {
      title: "Revoke Doc User Role",
      description: "Remove one user's explicit role on a document. They fall back to the document's default role.",
      inputSchema: { workspaceId: WorkspaceIdArg, docId: z.string(), userId: z.string() },
    },
    wrap("revoke_doc_user_role_failed", async (a: { workspaceId?: string; docId: string; userId: string }) => {
      const input = { workspaceId: wsId(a.workspaceId), docId: a.docId, userId: a.userId };
      const data = await gql.request<{ revokeDocUserRoles: boolean }>(OPERATIONS.revokeDocUserRole, { input });
      return done(data.revokeDocUserRoles, "the role revocation", { docId: a.docId, userId: a.userId });
    }) as any,
  );

  server.registerTool(
    "set_doc_default_role",
    {
      title: "Set Doc Default Role",
      description: "Set the role every other workspace member gets on a document (for example Reader, or None to make it private to people with explicit roles).",
      inputSchema: { workspaceId: WorkspaceIdArg, docId: z.string(), role: DocRoleArg },
    },
    wrap("set_doc_default_role_failed", async (a: { workspaceId?: string; docId: string; role: string }) => {
      const input = { workspaceId: wsId(a.workspaceId), docId: a.docId, role: a.role };
      const data = await gql.request<{ updateDocDefaultRole: boolean }>(OPERATIONS.updateDocDefaultRole, { input });
      return done(data.updateDocDefaultRole, "the default role change", { docId: a.docId, role: a.role });
    }) as any,
  );

  // ---------------------------------------------------------------- replies
  server.registerTool(
    "create_reply",
    {
      title: "Create Reply",
      description: "Reply to an existing comment thread. Find the commentId with list_comments. Plain text is wrapped into a paragraph snapshot.",
      inputSchema: {
        commentId: z.string(),
        docTitle: z.string().describe("Title of the document the comment is on (stored with the reply for notifications)."),
        docMode: z.enum(["page", "edgeless"]).optional(),
        content: z.union([z.string(), z.record(z.unknown())]).describe("Reply text, or a native { snapshot } payload."),
        mentions: z.array(z.string()).optional().describe("User ids to mention."),
      },
    },
    wrap("create_reply_failed", async (a: { commentId: string; docTitle: string; docMode?: string; content: unknown; mentions?: string[] }) => {
      const input = { commentId: a.commentId, docTitle: a.docTitle, docMode: a.docMode === "edgeless" ? "edgeless" : "page", content: normalizeCommentContent(a.content as any), mentions: a.mentions };
      const data = await gql.request<{ createReply: any }>(OPERATIONS.createReply, { input });
      return { ok: true, reply: data.createReply, id: data.createReply.id };
    }) as any,
  );

  server.registerTool(
    "update_reply",
    {
      title: "Update Reply",
      description: "Edit the content of one of your own replies.",
      inputSchema: { replyId: z.string(), content: z.union([z.string(), z.record(z.unknown())]) },
    },
    wrap("update_reply_failed", async (a: { replyId: string; content: unknown }) => {
      const input = { id: a.replyId, content: normalizeCommentContent(a.content as any) };
      const data = await gql.request<{ updateReply: boolean }>(OPERATIONS.updateReply, { input });
      return done(data.updateReply, "the reply update", { replyId: a.replyId });
    }) as any,
  );

  server.registerTool(
    "delete_reply",
    {
      title: "Delete Reply",
      description: "Delete a reply. Pass confirmReplyId equal to replyId.",
      inputSchema: { replyId: z.string(), confirmReplyId: confirmed("replyId") },
    },
    wrap("delete_reply_failed", async (a: { replyId: string; confirmReplyId: string }) => {
      requireMatchingConfirmation("delete_reply", a.replyId, a.confirmReplyId);
      const data = await gql.request<{ deleteReply: boolean }>(OPERATIONS.deleteReply, { id: a.replyId });
      return done(data.deleteReply, "the reply deletion", { replyId: a.replyId });
    }) as any,
  );

  // ------------------------------------------------------- MCP credentials
  server.registerTool(
    "list_mcp_credentials",
    {
      title: "List MCP Credentials",
      description: "List AFFiNE's own per-workspace MCP credentials (the ones its built-in /api/workspaces/<id>/mcp endpoint accepts). Shows fingerprint, access mode, status and expiry; never the token.",
      inputSchema: { workspaceId: WorkspaceIdArg },
    },
    wrap("list_mcp_credentials_failed", async (a: { workspaceId?: string }) => {
      const data = await gql.request<{ mcpCredentials: any[] }>(OPERATIONS.listMcpCredentials, { workspaceId: wsId(a.workspaceId) });
      return { items: data.mcpCredentials };
    }) as any,
  );

  server.registerTool(
    "create_mcp_credential",
    {
      title: "Create MCP Credential",
      description: "Mint a new workspace MCP credential. The returned token is shown ONCE and is a secret: store it in a secret manager, never in a repo or chat log.",
      inputSchema: {
        workspaceId: WorkspaceIdArg,
        name: z.string().min(1).max(100),
        accessMode: z.enum(["READ_ONLY", "READ_WRITE"]).optional().describe("Defaults to READ_ONLY."),
        expirationDays: z.number().int().min(1).max(365).optional().describe("Defaults to 90."),
      },
    },
    wrap("create_mcp_credential_failed", async (a: { workspaceId?: string; name: string; accessMode?: string; expirationDays?: number }) => {
      const input = { workspaceId: wsId(a.workspaceId), name: a.name, accessMode: a.accessMode ?? "READ_ONLY", expirationDays: a.expirationDays ?? 90 };
      const data = await gql.request<{ createMcpCredential: any }>(OPERATIONS.createMcpCredential, { input });
      return { ok: true, token: data.createMcpCredential.token, credential: data.createMcpCredential.credential };
    }) as any,
  );

  server.registerTool(
    "rotate_mcp_credential",
    {
      title: "Rotate MCP Credential",
      description: "Issue a replacement token for an existing credential; the old one keeps working for a grace period (see graceEndsAt). The new token is shown ONCE.",
      inputSchema: { workspaceId: WorkspaceIdArg, credentialId: z.string(), expirationDays: z.number().int().min(1).max(365).optional().describe("Defaults to 90.") },
    },
    wrap("rotate_mcp_credential_failed", async (a: { workspaceId?: string; credentialId: string; expirationDays?: number }) => {
      const data = await gql.request<{ rotateMcpCredential: any }>(OPERATIONS.rotateMcpCredential, { workspaceId: wsId(a.workspaceId), id: a.credentialId, expirationDays: a.expirationDays ?? 90 });
      return { ok: true, token: data.rotateMcpCredential.token, credential: data.rotateMcpCredential.credential };
    }) as any,
  );

  server.registerTool(
    "revoke_mcp_credential",
    {
      title: "Revoke MCP Credential",
      description: "Revoke a workspace MCP credential immediately. Pass confirmCredentialId equal to credentialId.",
      inputSchema: { workspaceId: WorkspaceIdArg, credentialId: z.string(), confirmCredentialId: confirmed("credentialId") },
    },
    wrap("revoke_mcp_credential_failed", async (a: { workspaceId?: string; credentialId: string; confirmCredentialId: string }) => {
      requireMatchingConfirmation("revoke_mcp_credential", a.credentialId, a.confirmCredentialId);
      const data = await gql.request<{ revokeMcpCredential: boolean }>(OPERATIONS.revokeMcpCredential, { workspaceId: wsId(a.workspaceId), id: a.credentialId });
      return done(data.revokeMcpCredential, "the credential revocation", { credentialId: a.credentialId });
    }) as any,
  );

  // -------------------------------------------------------------- embedding
  server.registerTool(
    "set_embedding_ignored_docs",
    {
      title: "Set Embedding Ignored Docs",
      description: "Add or remove documents from the workspace's AI-embedding ignore list, so they are excluded from (or restored to) semantic search and AI context. Returns the resulting ignored count.",
      inputSchema: {
        workspaceId: WorkspaceIdArg,
        add: z.array(z.string()).optional().describe("Doc ids to exclude from embeddings."),
        remove: z.array(z.string()).optional().describe("Doc ids to include again."),
      },
    },
    wrap("set_embedding_ignored_docs_failed", async (a: { workspaceId?: string; add?: string[]; remove?: string[] }) => {
      if (!a.add?.length && !a.remove?.length) throw new Error("set_embedding_ignored_docs requires add and/or remove.");
      const data = await gql.request<{ updateWorkspaceEmbeddingIgnoredDocs: number }>(OPERATIONS.embeddingIgnoredDocs, { workspaceId: wsId(a.workspaceId), add: a.add, remove: a.remove });
      return { ok: true, ignoredCount: data.updateWorkspaceEmbeddingIgnoredDocs };
    }) as any,
  );

  // ------------------------------------------------------------ server admin
  server.registerTool(
    "admin_dashboard",
    {
      title: "Admin Dashboard",
      description: "Server-wide metrics for the AFFiNE admin panel: active sync users, copilot conversations, storage. Requires the server Admin role. Cloud-only: a self-hosted AFFiNE answers \"Resource not found\".",
      inputSchema: {
        timezone: z.string().optional().describe("IANA timezone for day buckets. Defaults to UTC."),
        storageHistoryDays: z.number().int().min(1).max(365).optional(),
      },
    },
    wrap("admin_dashboard_failed", async (a: { timezone?: string; storageHistoryDays?: number }) => {
      const input = { timezone: a.timezone, storageHistoryDays: a.storageHistoryDays };
      const data = await cloudOnly(gql.request<{ adminDashboard: any }>(OPERATIONS.adminDashboard, { input }));
      return { dashboard: data.adminDashboard };
    }) as any,
  );

  server.registerTool(
    "admin_list_workspaces",
    {
      title: "Admin List Workspaces",
      description: "List every workspace on the server with owner, sizes and feature flags. Requires the server Admin role. Cloud-only: a self-hosted AFFiNE answers \"Resource not found\"; use list_workspaces instead.",
      inputSchema: { keyword: z.string().optional(), first: PageSize, skip: Offset },
    },
    wrap("admin_list_workspaces_failed", async (a: { keyword?: string; first?: number; skip?: number }) => {
      const filter = { keyword: a.keyword, first: a.first ?? 20, skip: a.skip ?? 0 };
      const data = await cloudOnly(gql.request<{ adminWorkspacesCount: number; adminWorkspaces: any[] }>(OPERATIONS.adminWorkspaces, { filter }));
      return { totalCount: data.adminWorkspacesCount, items: data.adminWorkspaces };
    }) as any,
  );

  server.registerTool(
    "admin_get_workspace",
    {
      title: "Admin Get Workspace",
      description: "One workspace in admin detail, including its members. Requires the server Admin role. Cloud-only: a self-hosted AFFiNE answers \"Resource not found\"; use get_workspace and list_workspace_members instead.",
      inputSchema: { workspaceId: z.string(), memberLimit: PageSize },
    },
    wrap("admin_get_workspace_failed", async (a: { workspaceId: string; memberLimit?: number }) => {
      const data = await cloudOnly(gql.request<{ adminWorkspace: any }>(OPERATIONS.adminWorkspace, { id: a.workspaceId, take: a.memberLimit }));
      return { workspace: data.adminWorkspace };
    }) as any,
  );

  server.registerTool(
    "list_users",
    {
      title: "List Users",
      description: "List accounts on the server (admin). Requires the server Admin role.",
      inputSchema: { keyword: z.string().optional().describe("Match name or email."), first: PageSize, skip: Offset },
    },
    wrap("list_users_failed", async (a: { keyword?: string; first?: number; skip?: number }) => {
      const filter = { keyword: a.keyword, first: a.first ?? 20, skip: a.skip ?? 0 };
      const data = await gql.request<{ usersCount: number; users: any[] }>(OPERATIONS.listUsers, { filter });
      return { totalCount: data.usersCount, items: data.users };
    }) as any,
  );

  server.registerTool(
    "get_user",
    {
      title: "Get User",
      description: "Look up one account by exact email (admin). Returns null if there is none.",
      inputSchema: { email: z.string().email() },
    },
    wrap("get_user_failed", async (a: { email: string }) => {
      const data = await gql.request<{ userByEmail: any }>(OPERATIONS.getUser, { email: a.email });
      return { user: data.userByEmail ?? null };
    }) as any,
  );

  server.registerTool(
    "create_user",
    {
      title: "Create User",
      description: "Create an account (admin). Omit password to create it without one (the user signs in by magic link or SSO). Do not put real passwords into chat logs.",
      inputSchema: { email: z.string().email(), name: z.string().optional(), password: z.string().min(8).max(256).optional() },
    },
    wrap("create_user_failed", async (a: { email: string; name?: string; password?: string }) => {
      const data = await gql.request<{ createUser: any }>(OPERATIONS.createUser, { input: { email: a.email, name: a.name, password: a.password } });
      return { ok: true, user: data.createUser };
    }) as any,
  );

  server.registerTool(
    "update_user",
    {
      title: "Update User",
      description: "Change an account's name or email (admin). At least one field is required.",
      inputSchema: { userId: z.string(), name: z.string().optional(), email: z.string().email().optional() },
    },
    wrap("update_user_failed", async (a: { userId: string; name?: string; email?: string }) => {
      if (a.name === undefined && a.email === undefined) throw new Error("update_user requires name and/or email.");
      const data = await gql.request<{ updateUser: any }>(OPERATIONS.updateUser, { id: a.userId, input: { name: a.name, email: a.email } });
      return { ok: true, user: data.updateUser };
    }) as any,
  );

  server.registerTool(
    "set_user_disabled",
    {
      title: "Set User Disabled",
      description: "Disable (ban) or re-enable an account (admin). Disabling is reversible. Pass confirmUserId equal to userId when disabling.",
      inputSchema: { userId: z.string(), disabled: z.boolean(), confirmUserId: z.string().optional().describe("Required when disabled=true; must equal userId.") },
    },
    wrap("set_user_disabled_failed", async (a: { userId: string; disabled: boolean; confirmUserId?: string }) => {
      if (a.disabled) requireMatchingConfirmation("set_user_disabled", a.userId, a.confirmUserId);
      const data = a.disabled
        ? (await gql.request<{ banUser: any }>(OPERATIONS.banUser, { id: a.userId })).banUser
        : (await gql.request<{ enableUser: any }>(OPERATIONS.enableUser, { id: a.userId })).enableUser;
      return { ok: true, user: data };
    }) as any,
  );

  server.registerTool(
    "delete_user",
    {
      title: "Delete User",
      description: "Permanently delete an account (admin). Irreversible; prefer set_user_disabled. Pass confirmUserId equal to userId.",
      inputSchema: { userId: z.string(), confirmUserId: confirmed("userId") },
    },
    wrap("delete_user_failed", async (a: { userId: string; confirmUserId: string }) => {
      requireMatchingConfirmation("delete_user", a.userId, a.confirmUserId);
      const data = await gql.request<{ deleteUser: { success: boolean } }>(OPERATIONS.deleteUser, { id: a.userId });
      return done(data.deleteUser.success, "the user deletion", { userId: a.userId });
    }) as any,
  );

  server.registerTool(
    "get_app_config",
    {
      title: "Get App Config",
      description: "Read the server's effective configuration. Secret values (passwords, tokens, private keys, credentials inside URLs) are redacted by this server, because AFFiNE self-hosted does not mask them. includeMetadata adds value sources and is only available on AFFiNE builds that expose appConfigMetadata. Requires the server Admin role.",
      inputSchema: { includeMetadata: z.boolean().optional().describe("Also return value sources and secret status (larger).") },
    },
    wrap("get_app_config_failed", async (a: { includeMetadata?: boolean }) => {
      const data = await gql.request<{ appConfig: unknown }>(OPERATIONS.getAppConfig, {});
      const result: Record<string, unknown> = { config: redactConfig(data.appConfig) };
      if (a.includeMetadata) {
        try {
          const meta = await gql.request<{ appConfigMetadata: unknown }>(OPERATIONS.getAppConfigMetadata, {});
          result.metadata = redactConfig(meta.appConfigMetadata);
        } catch (error: any) {
          if (!/Cannot query field "appConfigMetadata"/.test(String(error?.message ?? error))) throw error;
          result.metadata = null;
          result.metadataUnavailable = "This AFFiNE server does not expose appConfigMetadata (it is missing on stable 0.27.4).";
        }
      }
      return result;
    }) as any,
  );

  server.registerTool(
    "validate_app_config",
    {
      title: "Validate App Config",
      description: "Dry-run a configuration change: reports whether each module/key/value is valid without applying it. Use before update_app_config.",
      inputSchema: {
        updates: z.array(z.object({ module: z.string(), key: z.string(), value: z.unknown().optional() })).min(1).max(50),
      },
    },
    wrap("validate_app_config_failed", async (a: { updates: Array<{ module: string; key: string; value?: unknown }> }) => {
      const data = await gql.request<{ validateAppConfig: any[] }>(OPERATIONS.validateAppConfig, { updates: a.updates });
      return { items: data.validateAppConfig, allValid: data.validateAppConfig.every((r: any) => r.valid) };
    }) as any,
  );

  server.registerTool(
    "update_app_config",
    {
      title: "Update App Config",
      description: "Change one server configuration value (admin; takes effect for every user, and some modules restart services). Validate first with validate_app_config. Pass confirmKey equal to \"<module>.<key>\".",
      inputSchema: {
        module: z.string(),
        key: z.string(),
        value: z.unknown().optional().describe("New value. Omit with clear=true to reset to the default."),
        clear: z.boolean().optional(),
        confirmKey: confirmed('"<module>.<key>"'),
      },
    },
    wrap("update_app_config_failed", async (a: { module: string; key: string; value?: unknown; clear?: boolean; confirmKey: string }) => {
      requireMatchingConfirmation("update_app_config", `${a.module}.${a.key}`, a.confirmKey);
      const update: Record<string, unknown> = { module: a.module, key: a.key };
      if (a.clear) update.clear = true; else update.value = a.value;
      const data = await gql.request<{ updateAppConfig: unknown }>(OPERATIONS.updateAppConfig, { updates: [update] });
      return { ok: true, config: data.updateAppConfig };
    }) as any,
  );

  // ------------------------------------------------------------ raw GraphQL
  server.registerTool(
    "graphql_execute",
    {
      title: "Execute GraphQL",
      description: "Escape hatch: run any GraphQL document against AFFiNE as the signed-in account. Queries run freely (use `{ __schema { queryType { fields { name } } } }` to discover operations). A document containing `mutation` or `subscription` is refused unless allowMutation=true, because it can change or delete anything the account may. Prefer the typed tools; use this only for operations they do not cover.",
      inputSchema: {
        query: z.string().min(1).max(100_000).describe("GraphQL document."),
        variables: z.record(z.unknown()).optional().describe("Variables object."),
        allowMutation: z.boolean().optional().describe("Must be true to run a mutation. Read the document twice first."),
      },
    },
    wrap("graphql_execute_failed", async (a: { query: string; variables?: Record<string, unknown>; allowMutation?: boolean }) => {
      if (graphqlDocumentWrites(a.query) && a.allowMutation !== true) {
        throw new Error("This document contains a mutation or subscription. Re-run with allowMutation=true if you intend to change data.");
      }
      const data = await gql.request<Record<string, unknown>>(a.query, a.variables ?? {});
      return { data };
    }) as any,
  );
}
