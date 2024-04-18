import dash_bootstrap_components as dbc
import dash
from dash import Input, Output, html, dcc, callback

from visualization.parser import data_visualizer
from visualization.template import page_container,plotly_template_dark,external_stylesheets

@staticmethod
def generate_hosts_DashDIV(error_text=f"data can't be parsed", show=False) -> html.Div:
    data = data_visualizer.generate_hosts_list()
    if not data: return [
            html.Span([
                dbc.Label(className="fa fa-moon", html_for="switch",
                style={'display': 'none'}
                ),
                #dbc.Switch( id="switch", value=False, className="d-inline-block ms-1", persistence=True),
                dbc.Switch( id="switch", value=False, className="d-md-none ms-1", persistence=True),
                dbc.Label(className="fa fa-sun", html_for="switch",
                style={'display': 'none'}
                ),
            ]),
            html.Div(error_text),
            data_visualizer.cannot_visualize()
    ]

    data.sort()
    return [
        html.Span([
            dbc.Label(className="fa fa-moon", html_for="switch",
            style={'display': 'none'}
            ),
            #dbc.Switch( id="switch", value=False, className="d-inline-block ms-1", persistence=True),
            dbc.Switch( id="switch", value=False, className="d-md-none ms-1", persistence=True),
            dbc.Label(className="fa fa-sun", html_for="switch",
            style={'display': 'none'}
            ),
        ]),
        html.Details(
            children=[
                html.Summary("Hostnames"),
                html.Div()
            ]
        ),
        html.Details(
            children=[
                html.Summary("IP"),
                html.Div(
                    [
                        html.Details(
                            children=[
                                html.Summary(
                                    host.replace('_','.')
                                ),
                                html.Div(
                                    [
                                        html.Span(
                                            f"Host MAC: {hdata['MAC']['src'][0]}"
                                        ) if 'MAC' in hdata and 'src' in hdata['MAC'] else html.Span(),
                                        html.Div([html.Details(
                                            children=[
                                                html.Summary(
                                                    f"DNS Queries"
                                                ),
                                                html.Ul(
                                                    children=[
                                                        html.Li(
                                                            host_query
                                                        )
                                                        for host_query in hdata['DNS']['queries']
                                                    ],
                                                    style={
                                                        'marginLeft': '1em'
                                                    }
                                                )
                                            ],
                                            style={
                                                'marginLeft': '1em'
                                            }
                                        )]) if 'DNS' in hdata and 'queries' in hdata['DNS'] else html.Div(),
                                        html.Div([html.Details(
                                            children=[
                                                html.Summary(
                                                    "Active connections"
                                                ),
                                                html.Ul(
                                                    children=[
                                                        html.Li(
                                                            ':'.join([x.strip() for x in connections[1:-1].split(',')])
                                                        )
                                                        for connections in hdata['active_tcp_connection']
                                                    ]
                                                )
                                            ]
                                        )]) if 'active_tcp_connection' in hdata else html.Div(),
                                        html.Div([html.Details(
                                            children=[
                                                html.Summary(
                                                    "Simple Service Discovery"
                                                ),
                                                html.Div([
                                                    html.Summary(
                                                        "Searching",
                                                        style={
                                                            'marginLeft': '1em'
                                                        }
                                                    ),
                                                    html.Ul(
                                                        children=[
                                                            html.Li(
                                                                children=[
                                                                    html.Span(children=[
                                                                        html.Pre(children=[
                                                                            str('\n'.join(probe))
                                                                        ])
                                                                    ])
                                                                ],
                                                                style={
                                                                    'marginLeft': '1em'
                                                                }
                                                            )
                                                            for probe in hdata['SSDP']['searching']
                                                        ],
                                                        style={
                                                            'marginLeft': '1em'
                                                        }
                                                    )],
                                                    style={
                                                        'marginLeft': '1em'
                                                    }
                                                ) if 'searching' in hdata['SSDP'] else html.Div([]),
                                                html.Div([
                                                    html.Summary(
                                                        "Advertising",
                                                        style={
                                                            'marginLeft': '1em'
                                                        }
                                                    ),
                                                    html.Ul(
                                                        children=[
                                                            html.Li(
                                                                children=[
                                                                    html.Span(children=[
                                                                        html.Pre(children=[
                                                                            str('\n'.join(advertisement))
                                                                        ])
                                                                    ])
                                                                ],
                                                                style={
                                                                    'marginLeft': '1em'
                                                                }
                                                            )
                                                            for advertisement in hdata['SSDP']['advertising']
                                                        ],
                                                        style={
                                                            'marginLeft': '1em'
                                                        }
                                                    )
                                                ]) if 'advertising' in hdata['SSDP'] else html.Div([]),
                                            ]
                                        )],
                                        style={
                                            'marginLeft': '1em'
                                        }) if 'SSDP' in hdata else html.Div(),
                                        html.Div([html.Details(
                                            children=[
                                                html.Summary(
                                                    "DNS Request/Replies"
                                                ),
                                                html.Div([
                                                    html.Details(
                                                        children=[
                                                            html.Summary(
                                                                "Requests",
                                                                style={
                                                                    'marginLeft': '1em'
                                                                }
                                                            ),
                                                            html.Ul(
                                                                children=[
                                                                    html.Ul(
                                                                        html.Li(
                                                                            children=[
                                                                                probe
                                                                            ],
                                                                            style={
                                                                                'marginLeft': '1em'
                                                                            }
                                                                        )
                                                                    )
                                                                    for probe in hdata['DNS']['queries']
                                                                ],
                                                                style={
                                                                    'marginLeft': '1em'
                                                                }
                                                            )
                                                        ],
                                                        style={
                                                            'marginLeft': '1em'
                                                        }
                                                    ) if 'queries' in hdata['DNS'] else html.Div([]),
                                                ]),
                                                html.Div([
                                                    html.Details(
                                                        children=[
                                                            html.Summary(
                                                                "Replies",
                                                                style={
                                                                    'marginLeft': '1em'
                                                                }
                                                            ),
                                                            html.Ul(
                                                                children=[
                                                                        (html.Li(
                                                                            children=[
                                                                                html.Li(children=[answer['result'][0]]),
                                                                                html.Plaintext(':'),
                                                                                html.Li(children=[answer['result'][1]]),
                                                                            ],
                                                                            style={
                                                                                'marginLeft': '1em'
                                                                            }
                                                                        ) if answer['subtype'] in ['SRV'] and 'result' in answer.keys() else html.Plaintext())
                                                                        for answer in hdata['DNS']['answers']
                                                                        (html.Li(
                                                                            children=[
                                                                                str("".join([str(x) for x in answer['result']]))
                                                                            ],
                                                                            style={
                                                                                'marginLeft': '1em'
                                                                            }
                                                                        ) if answer['subtype'] in ['A','PTR'] and 'result' in answer.keys() else html.Plaintext())
                                                                        for answer in hdata['DNS']['answers']
                                                                        (html.Li(
                                                                            children=[
                                                                                html.Ul(
                                                                                    children=[
                                                                                        html.Li(children=[answer['result'][0]]),
                                                                                        html.Li(children=[answer['result'][1]]),
                                                                                        html.Ul(
                                                                                            children=[
                                                                                                html.Li(children=[subres]) for subres in answer['result'][2]
                                                                                            ]
                                                                                        )
                                                                                    ]
                                                                                )
                                                                            ],
                                                                            style={
                                                                                'marginLeft': '1em'
                                                                            }
                                                                        ) if answer['subtype'] in ['TXT'] and 'result' in answer.keys() else html.Plaintext())
                                                                    for answer in hdata['DNS']['answers']
                                                                ],
                                                                style={
                                                                    'marginLeft': '1em'
                                                                }
                                                            )
                                                        ]
                                                    )
                                                ]) if 'answers' in hdata['DNS'] else html.Div([]),
                                            ]
                                        )],
                                        style={
                                            'marginLeft': '1em'
                                        }) if 'DNS' in hdata else html.Div(),
                                    ]
                                ),
                            ]
                        )
                        for host,hdata in data
                    ],
                    style={
                        'marginLeft': '1em'
                    }
                )
            ]
        )
    ]

dash.register_page(__name__)
layout = generate_hosts_DashDIV