from werkzeug.datastructures import WWWAuthenticate

from odoo import api, models, SUPERUSER_ID
from odoo.http import request


class IrHttp(models.AbstractModel):

    _inherit = 'ir.http'

    @classmethod
    def _get_mcp_challenge(cls, token):
        """Point MCP clients to the protected resource metadata (RFC 9728), which starts the OAuth flow."""
        challenge = WWWAuthenticate('bearer')
        challenge['resource_metadata'] = (
            request.httprequest.url_root.rstrip('/') + '/.well-known/oauth-protected-resource/mcp'
        )
        if token:
            challenge['error'] = 'invalid_token'
        return challenge

    @classmethod
    def _authenticate_mcp_token(cls, token):
        """Refuse MCP keys issued through OAuth once their access token has expired."""
        name = super()._authenticate_mcp_token(token)
        key = name and getattr(request, '_mcp_key', None)
        if key:
            env = api.Environment(request.env.cr, SUPERUSER_ID, {})
            if env['muk_mcp_oauth.grant']._is_key_expired(key.id):
                return None
        return name
