/**
 * App Store Connect MCP — remote stateless (Cloudflare Workers).
 *
 * MVP contract for other developers (BYOK):
 * - Each dev signs the Apple JWT LOCALLY with their own .p8 (never sent to the server).
 *   Helper: `bun run mint-jwt` (scripts/mint-apple-jwt.ts).
 * - Every tool that touches Apple requires `appleJwt` (ES256 JWT, aud
 *   `appstoreconnect-v1`, exp-iat <= 20min). The Worker only validates shape/
 *   expiry, then proxies to api.appstoreconnect.apple.com.
 * - The server has NO secrets, NO KV/D1, and NEVER logs JWTs.
 * - The ES256 signature is NOT verified here (no public key available): Apple is
 *   the source of truth — a bad signature comes back as an Apple 401 MCP error.
 *
 * Apple docs: https://developer.apple.com/documentation/appstoreconnectapi/generating-tokens-for-api-requests
 * Cloudflare docs: https://developers.cloudflare.com/agents/model-context-protocol/guides/remote-mcp-server/
 */

import { createMcpHandler } from "agents/mcp/server";
import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";

const BASE_URL = "https://api.appstoreconnect.apple.com";
const APPLE_AUD = "appstoreconnect-v1";
const MAX_LIFETIME_SEC = 20 * 60;

// --- JWT helpers (shape/expiry validation only, Web standards) ---

function base64UrlDecode(input: string): string {
  const b64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  // atob is available in the Workers runtime
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

interface AppleJwtClaims {
  kid: string;
  aud: string;
  exp: number;
  iat: number;
}

/** Validates shape + aud + expiry. Returns log-safe claims (never the JWT). */
function validateAppleJwt(appleJwt: string): AppleJwtClaims {
  const parts = appleJwt.split(".");
  if (parts.length !== 3) throw new Error("Invalid appleJwt: expected a 3-part JWT.");
  let header: { alg?: string; kid?: string };
  let payload: { aud?: string; exp?: number; iat?: number };
  try {
    header = JSON.parse(base64UrlDecode(parts[0]));
    payload = JSON.parse(base64UrlDecode(parts[1]));
  } catch {
    throw new Error("Invalid appleJwt: header/payload are not decodable.");
  }
  if (header.alg !== "ES256") throw new Error(`Invalid appleJwt: expected alg ES256, got ${header.alg ?? "?"} (sign with your .p8).`);
  if (!header.kid) throw new Error("Invalid appleJwt: header.kid is missing.");
  if (payload.aud !== APPLE_AUD) throw new Error(`Invalid appleJwt: expected aud ${APPLE_AUD}.`);
  if (typeof payload.exp !== "number" || typeof payload.iat !== "number")
    throw new Error("Invalid appleJwt: exp/iat are missing.");
  if (payload.exp - payload.iat > MAX_LIFETIME_SEC + 60)
    throw new Error("Invalid appleJwt: lifetime > 20 min (Apple rejects it, use 15 min max).");
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp <= now) throw new Error("Expired appleJwt: regenerate with `bun run mint-jwt`.");
  return { kid: header.kid, aud: payload.aud, exp: payload.exp, iat: payload.iat };
}

// --- Apple HTTP client (stateless, per-request JWT) ---

type HttpMethod = "GET" | "POST" | "PATCH" | "DELETE";
type QueryValue = string | number | boolean | (string | number | boolean)[];

interface AscRequestOptions {
  method?: HttpMethod;
  query?: Record<string, QueryValue>;
  body?: unknown;
  accept?: string;
  autoPaginate?: boolean;
  maxPages?: number;
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

function formatAppleErrors(payload: unknown, fallback: string): string {
  const errs = (payload as { errors?: Array<{ status?: string; code?: string; title?: string; detail?: string }> })?.errors;
  if (Array.isArray(errs) && errs.length) {
    return errs
      .map((e) => `[${e.status ?? "?"} ${e.code ?? "ERROR"}] ${e.title ?? ""}${e.detail ? ` — ${e.detail}` : ""}`)
      .join("\n");
  }
  return fallback.slice(0, 2000);
}

function parseTsv(textData: string, maxRows = 500) {
  const lines = textData.split(/\r?\n/).filter((l) => l.length > 0);
  if (!lines.length) return { headers: [], rowCount: 0, rows: [] };
  const headers = lines[0].split("\t");
  const rows = lines.slice(1, maxRows + 1).map((line) => {
    const cols = line.split("\t");
    const obj: Record<string, string> = {};
    headers.forEach((h, i) => {
      obj[h.trim()] = (cols[i] ?? "").trim();
    });
    return obj;
  });
  return {
    headers,
    rowCount: lines.length - 1,
    rows,
    truncated: lines.length - 1 > maxRows,
  };
}

async function gunzipToText(buf: ArrayBuffer): Promise<string> {
  const ds = new DecompressionStream("gzip");
  const stream = new Blob([buf]).stream().pipeThrough(ds);
  return await new Response(stream).text();
}

async function parseNonJson(res: Response, contentType: string) {
  const buf = await res.arrayBuffer();
  try {
    const out = await gunzipToText(buf);
    if (out.includes("\t")) {
      const parsed = parseTsv(out);
      return {
        _note: "sales/finance report gunzipped",
        contentType,
        sizeBytes: buf.byteLength,
        decompressedChars: out.length,
        ...parsed,
      };
    }
    return {
      _note: "decompressed non-JSON response",
      contentType,
      sizeBytes: buf.byteLength,
      textPreview: out.slice(0, 4000),
    };
  } catch {
    // non-gzip bytes: base64 preview (never log more)
    const bytes = new Uint8Array(buf).subarray(0, 2000);
    let binary = "";
    for (const b of bytes) binary += String.fromCharCode(b);
    return {
      _note: "non-JSON response (e.g. gzipped sales report)",
      contentType,
      sizeBytes: buf.byteLength,
      previewBase64: btoa(binary),
    };
  }
}

async function ascRequest(path: string, appleJwt: string, opts: AscRequestOptions = {}) {
  const {
    method = "GET",
    query = {},
    body,
    accept = "application/json",
    autoPaginate = true,
    maxPages = 10,
  } = opts;
  if (!path.startsWith("/v1/") && !path.startsWith("/v2/"))
    throw new Error("path must start with /v1/ or /v2/");
  if ((method === "POST" || method === "PATCH") && body === undefined)
    throw new Error(`${method} ${path} requires a JSON:API body.`);

  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (Array.isArray(v)) v.forEach((item) => qs.append(k, String(item)));
    else qs.set(k, String(v));
  }

  const doFetch = async (url: string) => {
    const headers: Record<string, string> = {
      Authorization: `Bearer ${appleJwt}`,
      Accept: accept,
    };
    const init: RequestInit = { method, headers };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    for (let attempt = 0; attempt < 3; attempt++) {
      const res = await fetch(url, init);
      if (res.status === 429 && attempt < 2) {
        const waitMs = Number(res.headers.get("retry-after") ?? "1") * 1000 + attempt * 1000;
        await sleep(Math.min(waitMs, 15000));
        continue;
      }
      return res;
    }
    throw new Error("unreachable");
  };

  const parseResponse = async (res: Response) => {
    const contentType = res.headers.get("content-type") ?? "";
    if (res.status === 204 || res.status === 200) {
      const len = res.headers.get("content-length");
      if (res.status === 204 || len === "0") return { success: true, status: res.status, path };
    }
    if (!res.ok) {
      const raw = await res.text();
      let detail = raw.slice(0, 2000);
      try {
        detail = formatAppleErrors(JSON.parse(raw), raw);
      } catch {
        /* non-JSON, use raw */
      }
      throw new Error(`ASC ${method} ${res.status} for ${path}:\n${detail}`);
    }
    if (contentType.includes("application/json") && accept.includes("application/json"))
      return await res.json();
    return parseNonJson(res, contentType);
  };

  const url = `${BASE_URL}${path}${qs.size ? `?${qs}` : ""}`;
  let res = await doFetch(url);
  let parsed: any = await parseResponse(res);

  if (method === "GET" && autoPaginate && parsed?.links?.next && Array.isArray(parsed?.data)) {
    const all = [...parsed.data];
    let pages = 1;
    let next: string | null = parsed.links.next;
    while (next && pages < maxPages) {
      res = await doFetch(next);
      parsed = await parseResponse(res);
      if (!Array.isArray(parsed?.data)) break;
      all.push(...parsed.data);
      pages++;
      next = parsed?.links?.next ?? null;
    }
    parsed.data = all;
    parsed._pagination = {
      pagesFetched: pages,
      totalReturned: all.length,
      truncated: next != null,
    };
  }
  return parsed;
}

async function ascFetch(path: string, appleJwt: string, query: Record<string, string | number> = {}, accept = "application/json") {
  return ascRequest(path, appleJwt, { method: "GET", query, accept });
}

function text(data: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
  };
}

// --- MCP server factory (stateless: fresh instance per request) ---

const appleJwtField = {
  appleJwt: z
    .string()
    .min(10)
    .describe(
      "App Store Connect JWT signed LOCALLY with your .p8 (aud appstoreconnect-v1, 20min max). Generate with: bun run mint-jwt. Your .p8 never leaves your machine."
    ),
};

function createServer() {
  const server = new McpServer({ name: "appstore-connect", version: "0.1.0" });

  server.registerTool(
    "validate_jwt",
    {
      description: "Validates the shape/expiry of your Apple JWT without calling Apple. Use it right after mint-jwt.",
      inputSchema: { ...appleJwtField },
    },
    async ({ appleJwt }) => {
      const claims = validateAppleJwt(appleJwt);
      return text({ valid: true, ...claims });
    }
  );

  server.registerTool(
    "list_apps",
    {
      description: "Lists the apps in your account (bundleId, sku, name).",
      inputSchema: { ...appleJwtField, limit: z.number().min(1).max(200).default(20) },
    },
    async ({ appleJwt, limit }) => {
      validateAppleJwt(appleJwt);
      return text(await ascFetch("/v1/apps", appleJwt, { limit, "fields[apps]": "name,bundleId,sku" }));
    }
  );

  server.registerTool(
    "get_app",
    {
      description: "Returns a single app.",
      inputSchema: { ...appleJwtField, appId: z.string().describe("App Store Connect ID (not the bundleId)") },
    },
    async ({ appleJwt, appId }) => {
      validateAppleJwt(appleJwt);
      return text(await ascFetch(`/v1/apps/${appId}`, appleJwt));
    }
  );

  server.registerTool(
    "list_app_store_versions",
    {
      description: "App Store versions (review state, versionString) for an app.",
      inputSchema: { ...appleJwtField, appId: z.string(), limit: z.number().min(1).max(200).default(20) },
    },
    async ({ appleJwt, appId, limit }) => {
      validateAppleJwt(appleJwt);
      return text(await ascFetch(`/v1/apps/${appId}/appStoreVersions`, appleJwt, { limit }));
    }
  );

  server.registerTool(
    "list_builds",
    {
      description: "Builds (version, processingState, expired), globally or per app.",
      inputSchema: { ...appleJwtField, appId: z.string().optional(), limit: z.number().min(1).max(200).default(20) },
    },
    async ({ appleJwt, appId, limit }) => {
      validateAppleJwt(appleJwt);
      return text(
        appId
          ? await ascFetch(`/v1/apps/${appId}/builds`, appleJwt, { limit })
          : await ascFetch("/v1/builds", appleJwt, { limit })
      );
    }
  );

  server.registerTool(
    "get_build",
    {
      description: "Returns a single build.",
      inputSchema: { ...appleJwtField, buildId: z.string() },
    },
    async ({ appleJwt, buildId }) => {
      validateAppleJwt(appleJwt);
      return text(await ascFetch(`/v1/builds/${buildId}`, appleJwt));
    }
  );

  server.registerTool(
    "list_beta_groups",
    {
      description: "TestFlight beta groups for an app (or global).",
      inputSchema: { ...appleJwtField, appId: z.string().optional(), limit: z.number().min(1).max(200).default(20) },
    },
    async ({ appleJwt, appId, limit }) => {
      validateAppleJwt(appleJwt);
      return text(
        appId
          ? await ascFetch(`/v1/apps/${appId}/betaGroups`, appleJwt, { limit })
          : await ascFetch("/v1/betaGroups", appleJwt, { limit })
      );
    }
  );

  server.registerTool(
    "list_beta_testers",
    {
      description: "Beta testers (email, name) for a beta group or global.",
      inputSchema: { ...appleJwtField, betaGroupId: z.string().optional(), limit: z.number().min(1).max(200).default(20) },
    },
    async ({ appleJwt, betaGroupId, limit }) => {
      validateAppleJwt(appleJwt);
      return text(
        betaGroupId
          ? await ascFetch(`/v1/betaGroups/${betaGroupId}/betaTesters`, appleJwt, { limit })
          : await ascFetch("/v1/betaTesters", appleJwt, { limit })
      );
    }
  );

  server.registerTool(
    "list_customer_reviews",
    {
      description: "Reviews and ratings for an app.",
      inputSchema: { ...appleJwtField, appId: z.string(), limit: z.number().min(1).max(200).default(20) },
    },
    async ({ appleJwt, appId, limit }) => {
      validateAppleJwt(appleJwt);
      return text(await ascFetch(`/v1/apps/${appId}/customerReviews`, appleJwt, { limit }));
    }
  );

  server.registerTool(
    "get_sales_report",
    {
      description:
        "Sales & Trends report. Requires vendorNumber (App Store Connect > Payments and Financial Reports). E.g. reportType=SALES, frequency=DAILY, reportDate=2026-09-01.",
      inputSchema: {
        ...appleJwtField,
        reportType: z.string().default("SALES"),
        frequency: z.enum(["DAILY", "WEEKLY", "MONTHLY", "YEARLY"]).default("DAILY"),
        reportDate: z.string().describe("YYYY-MM-DD"),
        vendorNumber: z.string(),
        reportSubType: z.string().optional(),
      },
    },
    async ({ appleJwt, reportType, frequency, reportDate, vendorNumber, reportSubType }) => {
      validateAppleJwt(appleJwt);
      const q: Record<string, string> = {
        "filter[reportType]": reportType,
        "filter[frequency]": frequency,
        "filter[reportDate]": reportDate,
        "filter[vendorNumber]": vendorNumber,
      };
      if (reportSubType) q["filter[reportSubType]"] = reportSubType;
      return text(await ascFetch("/v1/salesReports", appleJwt, q, "application/a-gzip"));
    }
  );

  server.registerTool(
    "asc_get",
    {
      description: "Generic passthrough for any App Store Connect GET endpoint. path must start with /v1/.",
      inputSchema: {
        ...appleJwtField,
        path: z.string().describe("E.g. /v1/apps, /v1/preReleaseVersions"),
        queryJson: z.string().optional().describe("JSON query object, e.g. '{\"limit\":10}'"),
      },
    },
    async ({ appleJwt, path, queryJson }) => {
      validateAppleJwt(appleJwt);
      if (!path.startsWith("/v1/")) throw new Error("path must start with /v1/");
      const query = queryJson ? (JSON.parse(queryJson) as Record<string, string | number>) : {};
      return text(await ascFetch(path, appleJwt, query));
    }
  );

  server.registerTool(
    "asc_request",
    {
      description:
        "Full passthrough: GET/POST/PATCH/DELETE on any /v1/ or /v2/ path. POST/PATCH require a JSON:API bodyJson. DELETE requires confirmDelete:true.",
      inputSchema: {
        ...appleJwtField,
        method: z.enum(["GET", "POST", "PATCH", "DELETE"]).default("GET"),
        path: z.string().describe("E.g. /v1/subscriptionIntroductoryOffers"),
        queryJson: z.string().optional().describe("JSON query object"),
        bodyJson: z.string().optional().describe("Serialized JSON:API body (required for POST/PATCH)"),
        autoPaginate: z.boolean().default(true).describe("Follows links.next and concatenates data[] (GET only)"),
        maxPages: z.number().min(1).max(50).default(10),
        confirmDelete: z.boolean().default(false).describe("Must be true to run DELETE"),
      },
    },
    async ({ appleJwt, method, path, queryJson, bodyJson, autoPaginate, maxPages, confirmDelete }) => {
      validateAppleJwt(appleJwt);
      if (method === "DELETE" && !confirmDelete)
        throw new Error("DELETE requires confirmDelete:true. Double-check the path and impact, then retry.");
      const query = queryJson ? (JSON.parse(queryJson) as Record<string, QueryValue>) : {};
      const body = bodyJson ? (JSON.parse(bodyJson) as unknown) : undefined;
      return text(await ascRequest(path, appleJwt, { method, query, body, autoPaginate, maxPages }));
    }
  );

  return server;
}

// Note: search_endpoints/describe_endpoint (6.8MB OpenAPI spec) are excluded from
// the MVP: they can't be bundled in the Worker. Phase 2: spec on R2 + search index.

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext) {
    return createMcpHandler(createServer)(request, env, ctx);
  },
};
