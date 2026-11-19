from odoo.http import request

from odoo.addons.muk_mcp.controllers.mcp import MCPController


class MCPControllerReadOnly(MCPController):

    def _get_tool_enforce_scope(self):
        """Read-only switch: every key is treated as read only while it is on (keys keep their own scope)."""
        if request.env['ir.config_parameter'].sudo().get_param('muk_mcp_oauth.read_only'):
            return 'read'
        return super()._get_tool_enforce_scope()
