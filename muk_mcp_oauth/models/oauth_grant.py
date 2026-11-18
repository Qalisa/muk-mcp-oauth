import base64
import hashlib
import hmac
import secrets

from datetime import timedelta

from odoo import api, fields, models

CODE_LIFETIME = timedelta(seconds=60)
ACCESS_LIFETIME = timedelta(hours=1)
REFRESH_LIFETIME = timedelta(days=30)

# OAuth scope -> MuK MCP key scope
SCOPES = {'mcp:read': 'read', 'mcp:write': 'write'}


def _hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def pkce_s256(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()


class OAuthGrant(models.Model):
    """One user's authorization of one client: the code, then the access key and refresh token it led to.

    Only hashes are stored. The access token is a MuK MCP key (``muk_mcp.key``) owned by the user, so
    everything MuK enforces on keys applies; this model adds its expiry and the refresh token.
    """

    _name = 'muk_mcp_oauth.grant'
    _description = "MCP OAuth Grant"
    _order = 'create_date desc'

    client_id = fields.Many2one('muk_mcp_oauth.client', required=True, ondelete='cascade', index=True)
    user_id = fields.Many2one('res.users', required=True, ondelete='cascade', index=True)
    scope = fields.Selection([('read', "Read Only"), ('write', "Read & Write")], required=True)

    code_hash = fields.Char(index=True, copy=False)
    code_challenge = fields.Char(copy=False)
    code_expires = fields.Datetime(copy=False)
    redirect_uri = fields.Char(copy=False)

    key_id = fields.Integer(string="MCP Key", copy=False, help="muk_mcp.key issued as access token.")
    access_expires = fields.Datetime(copy=False)
    refresh_hash = fields.Char(index=True, copy=False)
    refresh_expires = fields.Datetime(copy=False)

    # ----------------------------------------------------------
    # Scopes
    # ----------------------------------------------------------

    @api.model
    def _parse_scope(self, scope):
        """Requested OAuth scopes -> MuK key scope; read when none is asked. ``None`` when unknown."""
        asked = set((scope or '').split())
        if asked - set(SCOPES):
            return None
        return 'write' if 'mcp:write' in asked else 'read'

    @staticmethod
    def _oauth_scope(scope):
        return 'mcp:read mcp:write' if scope == 'write' else 'mcp:read'

    # ----------------------------------------------------------
    # Authorization code
    # ----------------------------------------------------------

    @api.model
    def _create_code(self, client, user, scope, redirect_uri, code_challenge):
        code = secrets.token_urlsafe(32)
        self.sudo().create({
            'client_id': client.id,
            'user_id': user.id,
            'scope': scope,
            'code_hash': _hash(code),
            'code_challenge': code_challenge,
            'code_expires': fields.Datetime.now() + CODE_LIFETIME,
            'redirect_uri': redirect_uri,
        })
        return code

    @api.model
    def _redeem_code(self, client, code, redirect_uri, code_verifier):
        """Single use: the code is cleared whatever the outcome. Returns the grant, or ``None``."""
        grant = self.sudo().search([('code_hash', '=', _hash(code or '')), ('client_id', '=', client.id)], limit=1)
        if not grant:
            return None
        valid = (
            grant.code_expires and grant.code_expires >= fields.Datetime.now()
            and grant.redirect_uri == redirect_uri
            and code_verifier and 43 <= len(code_verifier) <= 128
            and hmac.compare_digest(pkce_s256(code_verifier), grant.code_challenge or '')
        )
        grant.write({'code_hash': False, 'code_challenge': False, 'code_expires': False})
        if not valid:
            grant.unlink()
            return None
        return grant

    # ----------------------------------------------------------
    # Tokens
    # ----------------------------------------------------------

    def _issue_tokens(self):
        """Issue a new access key and refresh token, revoking the previous key (refresh token rotation)."""
        self.ensure_one()
        self._revoke_key()
        Key = self.env['muk_mcp.key'].sudo()
        rate_limit = int(self.env['ir.config_parameter'].sudo().get_param('muk_mcp.rate_limit_requests', 60))
        access_token = secrets.token_urlsafe(32)
        key = Key.create({
            'name': f"OAuth: {self.client_id.name}"[:100],
            'user_id': self.user_id.id,
            'key_hash': Key._hash_key(access_token),
            'key_prefix': access_token[:8],
            'scope': self.scope,
            'rate_limit': rate_limit,
        })
        refresh_token = secrets.token_urlsafe(32)
        now = fields.Datetime.now()
        self.write({
            'key_id': key.id,
            'access_expires': now + ACCESS_LIFETIME,
            'refresh_hash': _hash(refresh_token),
            'refresh_expires': now + REFRESH_LIFETIME,
        })
        return {
            'access_token': access_token,
            'token_type': 'Bearer',
            'expires_in': int(ACCESS_LIFETIME.total_seconds()),
            'refresh_token': refresh_token,
            'scope': self._oauth_scope(self.scope),
        }

    @api.model
    def _find_by_refresh_token(self, client, refresh_token):
        grant = self.sudo().search([
            ('refresh_hash', '=', _hash(refresh_token or '')),
            ('client_id', '=', client.id),
        ], limit=1)
        if grant and grant.refresh_expires and grant.refresh_expires >= fields.Datetime.now():
            return grant
        return None

    def _revoke_key(self):
        keys = self.env['muk_mcp.key'].sudo().browse([g.key_id for g in self if g.key_id]).exists()
        keys.unlink()

    def _revoke(self):
        """Revoke the access key and drop the grant (and so its refresh token)."""
        self._revoke_key()
        self.sudo().unlink()

    @api.model
    def _revoke_token(self, token):
        """RFC 7009: a refresh token or an access token; unknown tokens are not an error."""
        grants = self.sudo().search([('refresh_hash', '=', _hash(token or ''))])
        if not grants and token:
            key = self.env['muk_mcp.key'].sudo().authenticate(token)
            grants = key and self.sudo().search([('key_id', '=', key.id)])
        if grants:
            grants._revoke()

    # ----------------------------------------------------------
    # Access key expiry
    # ----------------------------------------------------------

    @api.model
    def _is_key_expired(self, key_id):
        grant = self.sudo().search([('key_id', '=', key_id)], limit=1)
        return bool(grant and grant.access_expires and grant.access_expires < fields.Datetime.now())

    @api.autovacuum
    def _gc_grants(self):
        now = fields.Datetime.now()
        # codes never redeemed
        self.sudo().search([('code_hash', '!=', False), ('code_expires', '<', now), ('key_id', '=', False)]).unlink()
        # expired access keys stay revoked; expired refresh tokens end the grant
        self.sudo().search([('access_expires', '<', now), ('key_id', '!=', False)])._revoke_key()
        self.sudo().search([('refresh_expires', '<', now)])._revoke()
