# muk-mcp-oauth

OAuth 2.1 for [MuK MCP Server](https://apps.odoo.com/apps/modules/18.0/muk_mcp) (`muk_mcp`) on Odoo 18:
MCP clients (Claude Code, Codex, ChatGPT, ...) connect by **logging the user in through Odoo in a browser**,
instead of the user creating an MCP key and pasting it.

```
claude mcp add --transport http odoo https://your-odoo.example.com/mcp
# then /mcp > odoo > Authenticate: the browser opens Odoo's login, then a consent page
```

The tokens it issues are **ordinary MuK MCP keys owned by the user** (`muk_mcp.key`): Odoo's access rights and
record rules, the key scope (read only / read & write), rate limiting and MuK's audit log all apply, and the
user sees and can revoke them among their MCP keys.

## What it adds

| Endpoint | |
|---|---|
| `/.well-known/oauth-protected-resource[/mcp]` | Protected resource metadata (RFC 9728), advertised in the `WWW-Authenticate` header of `/mcp`'s 401 |
| `/.well-known/oauth-authorization-server` | Authorization server metadata (RFC 8414) |
| `POST /oauth/register` | Dynamic client registration (RFC 7591), public clients only |
| `GET/POST /oauth/authorize` | Authorization code + PKCE (S256 only), behind Odoo's login, with a consent page |
| `POST /oauth/token` | Code exchange and refresh (rotating refresh tokens) |
| `POST /oauth/revoke` | Revocation (RFC 7009) of a refresh or access token |

- Scopes: `mcp:read` (default) and `mcp:write`, mapped to the MCP key scope.
- Lifetimes: code 60 s (single use, burnt by a failed attempt), access token 1 h, refresh token 30 days.
  Expired codes and grants are cleaned by Odoo's autovacuum.
- Only hashes of codes, refresh tokens and access keys are stored.

## Redirect URIs

Allowed at registration and authorization:

- **Loopback** `http://localhost`, `http://127.0.0.1`, `http://[::1]` on any port (native apps, RFC 8252), as used
  by Claude Code and Codex. The port may differ between registration and authorization.
- **Exact https URIs** of hosted clients, listed comma-separated in the system parameter
  `muk_mcp_oauth.allowed_redirect_uris`. It is created with the callbacks of Claude (`claude.ai` and `claude.com`,
  used by the desktop apps too) and ChatGPT (its fixed callback, which ChatGPT uses because this module returns `iss`
  in authorization responses, RFC 9207); empty it to allow only local clients.

Anything else is refused, and an authorization request with an unknown client or redirect URI is never redirected.

## Connect an AI tool

MuK's **Connect** wizard (Settings > MCP > Connect, a *Connect an AI tool* button in every user's profile, and the shareable link `/mcp/setup`)
gets step-by-step tabs for the Claude apps and ChatGPT, and sign-in commands for Claude Code and Codex.

## Install

Depends on `muk_mcp` (and its `muk_web_utils`). Put this repository in the `addons_path`, branch `18.0`, and
install `muk_mcp_oauth`. Registered clients are listed under Settings > Technical > OAuth Clients.

## Tests

```
odoo -d <db> -i muk_mcp_oauth --test-enable --test-tags /muk_mcp_oauth --stop-after-init
```

They run the whole flow over HTTP: discovery, the 401 challenge, registration, consent, the PKCE exchange, use on
`/mcp`, refresh rotation, revocation and expiry.

## License

LGPL-3, by Qalisa. Not affiliated with MuK IT.
