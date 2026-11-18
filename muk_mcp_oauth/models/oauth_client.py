import json
import secrets

from urllib.parse import urlsplit

from odoo import api, fields, models

LOOPBACK_HOSTS = {'localhost', '127.0.0.1', '[::1]', '::1'}


class OAuthClient(models.Model):
    """An MCP client registered through dynamic client registration (RFC 7591).

    Clients are public (no secret): PKCE protects the code exchange.
    """

    _name = 'muk_mcp_oauth.client'
    _description = "MCP OAuth Client"
    _order = 'create_date desc'

    name = fields.Char(required=True, readonly=True)
    client_id = fields.Char(string="Client ID", required=True, readonly=True, index=True, copy=False)
    redirect_uris = fields.Text(string="Redirect URIs", required=True, readonly=True, help="JSON list.")
    grant_ids = fields.One2many('muk_mcp_oauth.grant', 'client_id', string="Grants")

    _sql_constraints = [
        ('client_id_unique', 'UNIQUE(client_id)', "The client ID must be unique."),
    ]

    # ----------------------------------------------------------
    # Redirect URIs
    # ----------------------------------------------------------

    @api.model
    def _allowed_remote_redirect_uris(self):
        """Exact https redirect URIs of hosted clients (claude.ai, chatgpt.com, ...), from a system parameter."""
        value = self.env['ir.config_parameter'].sudo().get_param('muk_mcp_oauth.allowed_redirect_uris', '')
        return {uri.strip() for uri in value.split(',') if uri.strip()}

    @api.model
    def _is_loopback(self, uri):
        parts = urlsplit(uri)
        return parts.scheme == 'http' and (parts.hostname or '') in LOOPBACK_HOSTS | {'::1'}

    @api.model
    def _is_redirect_uri_allowed(self, uri):
        """Native apps on the loopback interface (RFC 8252), or an allow-listed https URI. Never a fragment."""
        if not uri or '#' in uri:
            return False
        return self._is_loopback(uri) or uri in self._allowed_remote_redirect_uris()

    def _uris(self):
        self.ensure_one()
        return json.loads(self.redirect_uris)

    def _matches_redirect_uri(self, uri):
        """Exact match, except the port of loopback URIs, which native apps pick at runtime (RFC 8252 §7.3)."""
        self.ensure_one()
        if not self._is_redirect_uri_allowed(uri):
            return False
        if uri in self._uris():
            return True
        if self._is_loopback(uri):
            asked = urlsplit(uri)
            for registered in filter(self._is_loopback, self._uris()):
                known = urlsplit(registered)
                if (known.hostname, known.path, known.query) == (asked.hostname, asked.path, asked.query):
                    return True
        return False

    # ----------------------------------------------------------
    # Registration
    # ----------------------------------------------------------

    @api.model
    def _register_client(self, name, redirect_uris):
        return self.sudo().create({
            'name': (name or "MCP client")[:100],
            'client_id': 'mcp_' + secrets.token_urlsafe(24),
            'redirect_uris': json.dumps(redirect_uris),
        })
