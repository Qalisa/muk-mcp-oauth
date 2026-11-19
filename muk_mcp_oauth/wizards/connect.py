from odoo import api, fields, models


class Connect(models.TransientModel):
    _inherit = 'muk_mcp.connect'

    claude_code_oauth_cmd = fields.Text(compute='_compute_oauth_snippets')
    codex_oauth_cmd = fields.Text(compute='_compute_oauth_snippets')
    setup_url = fields.Char(string="Link to share", compute='_compute_oauth_snippets')

    @api.depends('mcp_url')
    def _compute_oauth_snippets(self):
        for record in self:
            record.setup_url = record.mcp_url.removesuffix('/mcp') + '/mcp/setup'
            record.claude_code_oauth_cmd = (
                f'claude mcp add --transport http --scope user odoo {record.mcp_url}\n'
                'claude mcp login odoo'
            )
            record.codex_oauth_cmd = f'codex mcp add odoo --url {record.mcp_url}\ncodex mcp login odoo'
