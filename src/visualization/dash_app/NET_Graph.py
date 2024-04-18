import dash
from   dash import Input, Output, html, dcc, callback
import dash_bootstrap_components as dbc

from visualization.parser import data_visualizer, parser

dash.register_page(__name__)
layout = [
    html.Span([
            dbc.Label(className="fa fa-moon", html_for="switch",style={'display': 'none'}),
            dbc.Switch(id="switch", value=False, className="d-md-none ms-1", persistence=True),
            dbc.Label(className="fa fa-sun", html_for="switch", style={'display': 'none'}),
    ]),
    data_visualizer.generate_new_graph_DashDIV(parser_func=parser.parse_nodes_by_IPs, title="Network (constrained to L3 host interface definitions)")
]