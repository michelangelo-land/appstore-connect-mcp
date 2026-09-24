# App Store Connect MCP — remote stateless

[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white)](https://appstore.michelangelo.land/mcp) [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

> Live: `https://appstore.michelangelo.land/mcp`

A remote MCP server on Cloudflare Workers for the App Store Connect API.
**Multi-developer by design: nobody shares API keys.**

## How it works (BYOK stateless)

1. Each developer creates **their own** API key in App Store Connect:
   - Admins: `Users and Access > Integrations > Team Keys > Generate` (pick the
     minimum role, e.g. Developer)
   - Non-admins: your user profile > Individual Key (inherits your permissions;
     no Sales/Finance/Provisioning). Apple docs:
     `https://developer.apple.com/documentation/appstoreconnectapi/creating-api-keys-for-app-store-connect-api`
2. Sign the JWT **locally** (your `.p8` never leaves your machine):
   ```bash
   export ASC_ISSUER_ID="..." ASC_KEY_ID="..."
   export ASC_PRIVATE_KEY="$(cat AuthKey_XXXX.p8)"
   bun run mint-jwt
   ```
   Output: a JWT valid for 15 min (`aud appstoreconnect-v1`, `alg ES256`).
3. Pass the JWT as the `appleJwt` argument of every tool. The Worker validates
   shape/expiry and proxies to Apple. A bad signature comes back as an Apple 401 —
   never logged.

## Tools

`validate_jwt` (no Apple call) plus proxies: `list_apps, get_app,
list_app_store_versions, list_builds, get_build, list_beta_groups,
list_beta_testers, list_customer_reviews, get_sales_report, asc_get, asc_request`
(the last one needs `confirmDelete:true` for DELETE and auto-paginates `links.next`).

Out of the MVP scope: `search_endpoints` / `describe_endpoint` (the 6.8MB OpenAPI
spec can't be bundled in the Worker). Phase 2: spec on R2 + search index. Until
then use `asc_get` / `asc_request` with the paths from Apple's docs.

## Development

```bash
bun install
bun run type-check
bun run dev        # http://localhost:8788/mcp
bun run deploy     # https://appstore.michelangelo.land/mcp
```

Debug: `npx @modelcontextprotocol/inspector@latest` → point it at `/mcp` →
call `validate_jwt` with your JWT → then `list_apps`.

## Use from opencode

```jsonc
// opencode.jsonc (consumer project)
{
  "mcp": {
    "appstore-connect": {
      "type": "remote",
      "url": "https://appstore.michelangelo.land/mcp"
    }
  }
}
```

No secrets in the config. The flow is: `bun run mint-jwt` → paste the JWT as
`appleJwt` whenever the agent calls a tool (it expires every 15 min — Apple's
choice, 20 min max).

## Security (MVP)

- The Worker has no secrets, no KV, no D1. Zero storage = zero at-rest breach surface.
- Never logged: JWTs, `.p8` keys, full issuer IDs. Safe to log: `kid`, Apple
  status codes, latency.
- Apple's rate limit is **per key** (`X-Rate-Limit`, 429 + honored `Retry-After`
  with backoff, max 3 attempts): one tenant can't burn the others' quota. Use a
  dedicated key for the MCP, separate from CI.
- Revocation: delete the key in App Store Connect (`Users and Access > Keys`);
  already-issued JWTs die on their own within 15 min.
- Known limitation: the Worker does not verify the ES256 signature (no public
  key) — Apple does. Always serve over HTTPS and consider putting Cloudflare
  Access in front of `/mcp` to restrict who can call it.

## License

MIT — see [LICENSE](./LICENSE).
