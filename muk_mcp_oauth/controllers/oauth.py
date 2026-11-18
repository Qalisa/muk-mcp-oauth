import json
import logging

from urllib.parse import urlencode

from odoo import http
from odoo.http import request

_logger = logging.getLogger(__name__)

SCOPES_SUPPORTED = ['mcp:read', 'mcp:write']


def _base_url():
    return request.httprequest.url_root.rstrip('/')


def _json(payload, status=200):
    return request.make_json_response(payload, status=status, headers=[
        ('Cache-Control', 'no-store'),
        ('Pragma', 'no-cache'),
    ])


def _oauth_error(error, description, status=400):
    return _json({'error': error, 'error_description': description}, status=status)


class MCPOAuthController(http.Controller):

    # ----------------------------------------------------------
    # Discovery
    # ----------------------------------------------------------

    @http.route([
        '/.well-known/oauth-protected-resource',
        '/.well-known/oauth-protected-resource/mcp',
    ], type='http', auth='none', methods=['GET'], cors='*', csrf=False, save_session=False)
    def protected_resource_metadata(self):
        """RFC 9728: what protects /mcp."""
        base = _base_url()
        return _json({
            'resource': f'{base}/mcp',
            'authorization_servers': [base],
            'scopes_supported': SCOPES_SUPPORTED,
            'bearer_methods_supported': ['header'],
            'resource_name': "Odoo MCP",
        })

    @http.route([
        '/.well-known/oauth-authorization-server',
        '/.well-known/oauth-authorization-server/mcp',
    ], type='http', auth='none', methods=['GET'], cors='*', csrf=False, save_session=False)
    def authorization_server_metadata(self):
        """RFC 8414."""
        base = _base_url()
        return _json({
            'issuer': base,
            'authorization_endpoint': f'{base}/oauth/authorize',
            'token_endpoint': f'{base}/oauth/token',
            'registration_endpoint': f'{base}/oauth/register',
            'revocation_endpoint': f'{base}/oauth/revoke',
            'response_types_supported': ['code'],
            'grant_types_supported': ['authorization_code', 'refresh_token'],
            'code_challenge_methods_supported': ['S256'],
            'token_endpoint_auth_methods_supported': ['none'],
            'revocation_endpoint_auth_methods_supported': ['none'],
            'scopes_supported': SCOPES_SUPPORTED,
        })

    # ----------------------------------------------------------
    # Dynamic client registration (RFC 7591)
    # ----------------------------------------------------------

    @http.route('/oauth/register', type='http', auth='none', methods=['POST'], cors='*', csrf=False, save_session=False, readonly=False)
    def register(self):
        try:
            metadata = json.loads(request.httprequest.get_data() or b'{}')
            assert isinstance(metadata, dict)
        except (ValueError, AssertionError):
            return _oauth_error('invalid_client_metadata', "The body must be a JSON object.")
        uris = metadata.get('redirect_uris')
        if not isinstance(uris, list) or not uris or not all(isinstance(u, str) for u in uris):
            return _oauth_error('invalid_redirect_uri', "redirect_uris must be a non-empty list.")
        Client = request.env['muk_mcp_oauth.client'].sudo()
        refused = [uri for uri in uris if not Client._is_redirect_uri_allowed(uri)]
        if refused:
            return _oauth_error('invalid_redirect_uri', f"Redirect URI not allowed: {refused[0]}")
        if metadata.get('token_endpoint_auth_method', 'none') != 'none':
            return _oauth_error('invalid_client_metadata', "Only public clients (token_endpoint_auth_method none).")
        client = Client._register_client(metadata.get('client_name'), uris)
        _logger.info("MCP OAuth client registered: %s (%s)", client.name, client.client_id)
        return _json({
            'client_id': client.client_id,
            'client_id_issued_at': int(client.create_date.timestamp()),
            'client_name': client.name,
            'redirect_uris': uris,
            'grant_types': ['authorization_code', 'refresh_token'],
            'response_types': ['code'],
            'token_endpoint_auth_method': 'none',
        }, status=201)

    # ----------------------------------------------------------
    # Authorization
    # ----------------------------------------------------------

    def _check_authorize_request(self, params):
        """Return ``(client, redirect_uri, error)``. Without a valid client and redirect URI, never redirect."""
        client = request.env['muk_mcp_oauth.client'].sudo().search(
            [('client_id', '=', params.get('client_id') or '')], limit=1,
        )
        redirect_uri = params.get('redirect_uri') or ''
        if not client or not client._matches_redirect_uri(redirect_uri):
            return None, None, "Unknown client or redirect URI."
        if params.get('response_type') != 'code':
            return client, redirect_uri, 'unsupported_response_type'
        if params.get('code_challenge_method') != 'S256' or not params.get('code_challenge'):
            return client, redirect_uri, 'invalid_request'
        if request.env['muk_mcp_oauth.grant']._parse_scope(params.get('scope')) is None:
            return client, redirect_uri, 'invalid_scope'
        return client, redirect_uri, None

    def _redirect_back(self, redirect_uri, **query):
        separator = '&' if '?' in redirect_uri else '?'
        query = {k: v for k, v in query.items() if v}
        return request.redirect(f'{redirect_uri}{separator}{urlencode(query)}', local=False)

    @http.route('/oauth/authorize', type='http', auth='user', methods=['GET'], website=False)
    def authorize(self, **params):
        client, redirect_uri, error = self._check_authorize_request(params)
        if not client:
            return request.render('muk_mcp_oauth.authorize_error', {'message': error}, status=400)
        if error:
            return self._redirect_back(redirect_uri, error=error, state=params.get('state'))
        scope = request.env['muk_mcp_oauth.grant']._parse_scope(params.get('scope'))
        return request.render('muk_mcp_oauth.authorize', {
            'client': client,
            'scope': scope,
            'params': {k: params.get(k) for k in (
                'client_id', 'redirect_uri', 'response_type', 'code_challenge',
                'code_challenge_method', 'scope', 'state', 'resource',
            ) if params.get(k)},
        })

    @http.route('/oauth/authorize', type='http', auth='user', methods=['POST'], website=False, readonly=False)
    def authorize_decision(self, decision=None, **params):
        client, redirect_uri, error = self._check_authorize_request(params)
        if not client:
            return request.render('muk_mcp_oauth.authorize_error', {'message': error}, status=400)
        if error:
            return self._redirect_back(redirect_uri, error=error, state=params.get('state'))
        if decision != 'allow':
            return self._redirect_back(redirect_uri, error='access_denied', state=params.get('state'))
        Grant = request.env['muk_mcp_oauth.grant']
        code = Grant._create_code(
            client, request.env.user, Grant._parse_scope(params.get('scope')),
            redirect_uri, params['code_challenge'],
        )
        _logger.info("MCP OAuth: %s authorized %s", request.env.user.login, client.name)
        return self._redirect_back(redirect_uri, code=code, state=params.get('state'))

    # ----------------------------------------------------------
    # Token (RFC 6749 §4.1.3, §6) and revocation (RFC 7009)
    # ----------------------------------------------------------

    @http.route('/oauth/token', type='http', auth='none', methods=['POST'], cors='*', csrf=False, save_session=False, readonly=False)
    def token(self, **params):
        client = request.env['muk_mcp_oauth.client'].sudo().search(
            [('client_id', '=', params.get('client_id') or '')], limit=1,
        )
        if not client:
            return _oauth_error('invalid_client', "Unknown client.", status=401)
        Grant = request.env['muk_mcp_oauth.grant'].sudo()
        grant_type = params.get('grant_type')
        if grant_type == 'authorization_code':
            grant = Grant._redeem_code(client, params.get('code'), params.get('redirect_uri'), params.get('code_verifier'))
        elif grant_type == 'refresh_token':
            grant = Grant._find_by_refresh_token(client, params.get('refresh_token'))
        else:
            return _oauth_error('unsupported_grant_type', "authorization_code or refresh_token.")
        if not grant:
            return _oauth_error('invalid_grant', "Invalid, expired or already used code or refresh token.")
        if not grant.user_id.active:
            grant._revoke()
            return _oauth_error('invalid_grant', "The user is no longer active.")
        return _json(grant._issue_tokens())

    @http.route('/oauth/revoke', type='http', auth='none', methods=['POST'], cors='*', csrf=False, save_session=False, readonly=False)
    def revoke(self, token=None, **params):
        request.env['muk_mcp_oauth.grant'].sudo()._revoke_token(token)
        return _json({})
