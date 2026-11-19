from odoo import fields, models


class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    mcp_read_only = fields.Boolean(string="Read Only", config_parameter='muk_mcp_oauth.read_only')
