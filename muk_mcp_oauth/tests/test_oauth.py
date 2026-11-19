import json
import re
import secrets

from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

from odoo import fields
from odoo.tests import HttpCase, tagged

from odoo.addons.muk_mcp_oauth.models.oauth_grant import pkce_s256

REDIRECT = 'http://localhost:33418/callback'
INITIALIZE = {
    'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
    'params': {'protocolVersion': '2025-06-18', 'capabilities': {}, 'clientInfo': {'name': 'test', 'version': '1'}},
}


@tagged('post_install', '-at_install')
class TestMCPOAuth(HttpCase):

    # ----------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------

    def _post_json(self, path, payload, headers=None):
        return self.url_open(path, data=json.dumps(payload), headers={'Content-Type': 'application/json', **(headers or {})})

    def _register(self, redirect_uris=(REDIRECT,), name="Test client"):
        return self._post_json('/oauth/register', {'client_name': name, 'redirect_uris': list(redirect_uris)})

    def _mcp(self, access_token):
        return self._post_json('/mcp', INITIALIZE, headers={
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json, text/event-stream',
        })

    def _call_tool(self, access_token, name, arguments):
        headers = {'Authorization': f'Bearer {access_token}', 'Accept': 'application/json, text/event-stream'}
        init = self._post_json('/mcp', INITIALIZE, headers=headers)
        if session := init.headers.get('Mcp-Session-Id'):
            headers['Mcp-Session-Id'] = session
        self._post_json('/mcp', {'jsonrpc': '2.0', 'method': 'notifications/initialized'}, headers=headers)
        response = self._post_json('/mcp', {
            'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': name, 'arguments': arguments},
        }, headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()['result']

    def _authorize(self, client_id, verifier, scope='mcp:read', decision='allow', redirect_uri=REDIRECT):
        """Log in as admin, open the consent page and answer it. Returns the redirect's query."""
        self.authenticate('admin', 'admin')
        params = {
            'response_type': 'code', 'client_id': client_id, 'redirect_uri': redirect_uri,
            'code_challenge': pkce_s256(verifier), 'code_challenge_method': 'S256',
            'scope': scope, 'state': 'xyz',
        }
        page = self.url_open('/oauth/authorize?' + '&'.join(f'{k}={v}' for k, v in params.items()))
        self.assertEqual(page.status_code, 200, page.text[:500])
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
        answer = self.url_open('/oauth/authorize', data={**params, 'csrf_token': csrf, 'decision': decision},
                               allow_redirects=False)
        self.assertIn(answer.status_code, (302, 303), answer.text[:500])
        location = answer.headers['Location']
        self.assertTrue(location.startswith(redirect_uri.split('?')[0]), location)
        return {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}

    def _token(self, **data):
        return self.url_open('/oauth/token', data=data)

    def _full_flow(self, scope='mcp:read'):
        client_id = self._register().json()['client_id']
        verifier = secrets.token_urlsafe(48)
        query = self._authorize(client_id, verifier, scope=scope)
        response = self._token(grant_type='authorization_code', client_id=client_id, code=query['code'],
                               redirect_uri=REDIRECT, code_verifier=verifier)
        self.assertEqual(response.status_code, 200, response.text)
        return client_id, response.json()

    # ----------------------------------------------------------
    # Discovery
    # ----------------------------------------------------------

    def test_metadata(self):
        resource = self.url_open('/.well-known/oauth-protected-resource/mcp').json()
        self.assertTrue(resource['resource'].endswith('/mcp'))
        server = self.url_open('/.well-known/oauth-authorization-server').json()
        self.assertEqual(server['issuer'], resource['authorization_servers'][0])
        self.assertEqual(server['code_challenge_methods_supported'], ['S256'])
        self.assertTrue(server['registration_endpoint'].endswith('/oauth/register'))
        self.assertTrue(server['authorization_response_iss_parameter_supported'])

    def test_unauthenticated_mcp_points_to_metadata(self):
        response = self._post_json('/mcp', INITIALIZE, headers={'Accept': 'application/json, text/event-stream'})
        self.assertEqual(response.status_code, 401)
        self.assertIn('resource_metadata=', response.headers.get('WWW-Authenticate', ''))

    # ----------------------------------------------------------
    # Registration
    # ----------------------------------------------------------

    def test_register_redirect_uris(self):
        self.assertEqual(self._register().status_code, 201)
        self.assertEqual(self._register(['http://127.0.0.1:9999/cb']).status_code, 201)
        self.assertEqual(self._register(['https://evil.example/cb']).status_code, 400)
        self.assertEqual(self._register(['http://evil.example/cb']).status_code, 400)
        self.assertEqual(self._register(['http://localhost:1/cb#frag']).status_code, 400)
        self.env['ir.config_parameter'].sudo().set_param('muk_mcp_oauth.allowed_redirect_uris', 'https://claude.ai/cb')
        self.assertEqual(self._register(['https://claude.ai/cb']).status_code, 201)

    # ----------------------------------------------------------
    # Authorization code + PKCE
    # ----------------------------------------------------------

    def test_hosted_clients_allowed_by_default(self):
        for uri in ('https://claude.ai/api/mcp/auth_callback', 'https://chatgpt.com/connector_platform_oauth_redirect'):
            self.assertEqual(self._register([uri]).status_code, 201, uri)

    def test_connect_wizard(self):
        wizard = self.env['muk_mcp.connect'].create({})
        self.assertIn(f'claude mcp add --transport http --scope user odoo {wizard.mcp_url}', wizard.claude_code_oauth_cmd)
        self.assertIn(wizard.mcp_url, wizard.codex_oauth_cmd)
        self.assertIn('claude mcp login odoo', wizard.claude_code_oauth_cmd)

    def test_full_flow_read(self):
        _client_id, tokens = self._full_flow()
        self.assertEqual(tokens['token_type'], 'Bearer')
        self.assertEqual(tokens['scope'], 'mcp:read')
        self.assertEqual(self._mcp(tokens['access_token']).status_code, 200)
        key = self.env['muk_mcp.key'].sudo().authenticate(tokens['access_token'])
        self.assertEqual(key.user_id, self.env.ref('base.user_admin'))
        self.assertEqual(key.scope, 'read')

    def test_offline_access_scope(self):
        _client_id, tokens = self._full_flow(scope='mcp:read offline_access')
        self.assertTrue(tokens['refresh_token'])

    def test_read_only_switch(self):
        _client_id, tokens = self._full_flow(scope='mcp:read mcp:write')
        create = {'model': 'res.partner.category', 'values': {'name': 'mcp-read-only'}}
        param = self.env['ir.config_parameter'].sudo()
        param.set_param('muk_mcp_oauth.read_only', 'True')
        self.assertTrue(self._call_tool(tokens['access_token'], 'create_records', create).get('isError'))
        self.assertFalse(self._call_tool(tokens['access_token'], 'search_count', {'model': 'res.partner'}).get('isError'))
        param.set_param('muk_mcp_oauth.read_only', False)
        self.assertFalse(self._call_tool(tokens['access_token'], 'create_records', create).get('isError'))

    def test_write_scope(self):
        _client_id, tokens = self._full_flow(scope='mcp:read mcp:write')
        self.assertEqual(self.env['muk_mcp.key'].sudo().authenticate(tokens['access_token']).scope, 'write')

    def test_loopback_port_may_change(self):
        client_id = self._register().json()['client_id']
        verifier = secrets.token_urlsafe(48)
        query = self._authorize(client_id, verifier, redirect_uri='http://localhost:51515/callback')
        self.assertIn('code', query)

    def test_deny(self):
        client_id = self._register().json()['client_id']
        query = self._authorize(client_id, secrets.token_urlsafe(48), decision='deny')
        self.assertEqual(query['error'], 'access_denied')
        self.assertEqual(query['state'], 'xyz')
        self.assertEqual(query['iss'], self.url_open('/.well-known/oauth-authorization-server').json()['issuer'])

    def test_wrong_verifier_and_code_reuse(self):
        client_id = self._register().json()['client_id']
        verifier = secrets.token_urlsafe(48)
        code = self._authorize(client_id, verifier)['code']
        wrong = self._token(grant_type='authorization_code', client_id=client_id, code=code,
                            redirect_uri=REDIRECT, code_verifier=secrets.token_urlsafe(48))
        self.assertEqual(wrong.json()['error'], 'invalid_grant')
        # the code was burnt by the failed attempt
        again = self._token(grant_type='authorization_code', client_id=client_id, code=code,
                            redirect_uri=REDIRECT, code_verifier=verifier)
        self.assertEqual(again.json()['error'], 'invalid_grant')

    def test_unknown_redirect_is_not_followed(self):
        client_id = self._register().json()['client_id']
        self.authenticate('admin', 'admin')
        page = self.url_open(f'/oauth/authorize?response_type=code&client_id={client_id}'
                             f'&redirect_uri=https://evil.example/cb&code_challenge=x&code_challenge_method=S256',
                             allow_redirects=False)
        self.assertEqual(page.status_code, 400)

    # ----------------------------------------------------------
    # Refresh, revocation, expiry
    # ----------------------------------------------------------

    def test_refresh_rotates(self):
        client_id, tokens = self._full_flow()
        refreshed = self._token(grant_type='refresh_token', client_id=client_id, refresh_token=tokens['refresh_token'])
        self.assertEqual(refreshed.status_code, 200, refreshed.text)
        new = refreshed.json()
        self.assertEqual(self._mcp(new['access_token']).status_code, 200)
        self.assertEqual(self._mcp(tokens['access_token']).status_code, 401)
        reused = self._token(grant_type='refresh_token', client_id=client_id, refresh_token=tokens['refresh_token'])
        self.assertEqual(reused.json()['error'], 'invalid_grant')

    def test_revoke(self):
        client_id, tokens = self._full_flow()
        self.assertEqual(self.url_open('/oauth/revoke', data={'token': tokens['refresh_token']}).status_code, 200)
        self.assertEqual(self._mcp(tokens['access_token']).status_code, 401)
        refreshed = self._token(grant_type='refresh_token', client_id=client_id, refresh_token=tokens['refresh_token'])
        self.assertEqual(refreshed.json()['error'], 'invalid_grant')

    def test_expired_access_token(self):
        _client_id, tokens = self._full_flow()
        key = self.env['muk_mcp.key'].sudo().authenticate(tokens['access_token'])
        grant = self.env['muk_mcp_oauth.grant'].sudo().search([('key_id', '=', key.id)])
        grant.access_expires = fields.Datetime.now() - timedelta(seconds=1)
        response = self._mcp(tokens['access_token'])
        self.assertEqual(response.status_code, 401)
        self.assertIn('invalid_token', response.headers.get('WWW-Authenticate', ''))
