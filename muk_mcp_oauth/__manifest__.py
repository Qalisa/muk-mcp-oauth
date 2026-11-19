{
    'name': "MuK MCP OAuth",
    'summary': "OAuth 2.1 (PKCE, dynamic client registration) for MuK MCP Server clients",
    'description': """
Lets MCP clients (Claude Code, Codex, ChatGPT, ...) connect to MuK MCP Server
by logging the user in through Odoo in a browser, instead of pasting an MCP key.
The tokens it issues are ordinary MuK MCP keys owned by that user, so Odoo's
access rights, the key scope, rate limiting and the audit log all apply.
""",
    'version': '18.0.1.4.0',
    'category': 'Productivity/Discuss',
    'license': 'LGPL-3',
    'author': "Qalisa",
    'website': "https://github.com/Qalisa/muk-mcp-oauth",
    'depends': ['muk_mcp'],
    'data': [
        'security/ir.model.access.csv',
        'views/templates.xml',
        'data/ir_config_parameter.xml',
        'views/client_views.xml',
        'views/connect_views.xml',
    ],
    'assets': {
        'web.assets_backend': ['muk_mcp_oauth/static/src/scss/connect.scss'],
    },
    'installable': True,
    'application': False,
}
