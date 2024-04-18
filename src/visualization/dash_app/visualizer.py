import plotly.graph_objects as go
import networkx as nx
import numpy as np
import json

import dash
from dash import dcc,html,clientside_callback,ClientsideFunction,State,callback
from dash_extensions import WebSocket
from dash_extensions.enrich import DashProxy, Output, Input
import dash_bootstrap_components as dbc

from time import sleep
from datetime import datetime

from visualization.parser import data_visualizer
from visualization.template import plotly_template_dark,external_stylesheets

mac_element_id="mac-graph-root"
net_element_id="net-graph-root"
host_element_id="hosts-root"


"""
I tried, dash, I really did.

Just going to optimize with js....

"""
# # Update page
# @callback(
#     Output(mac_element_id, "children"), 
#     Input("ws", "message"),
# )
# def mac_graph_update(message):
#     if message==None or 'data' in message.keys() and message['data'] == 'rerender-ram-cache':
#         print("Regenerating from ram-cache....")
        # g = [
        #     html.Iframe(
        #         id='mac-graph-frame',
        #         src='/mac-graph',
        #         width='50%',
        #         height='100%',
        #         style={
        #             'minHeight':'450px'
        #         },
        #         className='refreshing' #SipsTea
        #     )
        # ]
#         return g
#     else: 
#         print(f"Unknown ws message: {message}")
#         return []


dash.register_page(__name__, path='/')

layout=[
    html.Span([
            dbc.Label(className="fa fa-moon", html_for="switch"),
            dbc.Switch( id="switch", value=False, className="d-inline-block ms-1", persistence=True),
            dbc.Label(className="fa fa-sun", html_for="switch"),
    ]),
    dcc.Location(id="url", refresh=False), 
    WebSocket(id="ws", url="ws://127.0.0.1:8052/MAC_Graph_auto"),
    html.Div([
        html.Div([
            html.Div([
                dcc.Loading(
                    id=mac_element_id,
                    children=[
                        html.Iframe(
                            id='mac-graph-frame',
                            src='/mac-graph',
                            className='refreshing', #SipsTea
                            style={
                                'display':'table-cell',
                                'width':'100%',
                                'minWidth': '600px',
                                'minHeight':'450px'
                            },
                        )
                    ],
                    type="circle",
                )
                ],
                style={
                    'display':'table-cell',
                    'maxWidth':'50%',
                    'minWidth': '600px',
                    'minHeight':'450px'
                },
            ),
            html.Div([
                dcc.Loading(
                    id=net_element_id,
                    children=[
                        html.Iframe(
                            id='net-graph-frame',
                            src='/net-graph',
                            className='refreshing', #SipsTea
                            style={
                                'display':'table-cell',
                                'width':'100%',
                                'minWidth': '600px',
                                'minHeight':'450px'
                            },
                        )
                    ],
                    type="circle",
                    style={
                        'minHeight':'450px'
                    },
                )
                ],
                style={
                    'display':'table-cell',
                    'maxWidth':'50%',
                    'minWidth': '600px',
                    'minHeight':'500px'
                },
            ),
        ],
        style={
            'display':'table-row'
        })
    ],
    style={
        'width':'100%',
        'display':'table'
    }),
    html.Div([
        html.Div([
            html.Div([
                dcc.Loading(
                    id='host-details',
                    children=[
                        html.Iframe(
                            id='hosts-frame',
                            src='/hosts-describe',
                            style={
                                'display':'table-cell',
                                'width':'100%',
                                'minWidth': '600px',
                                'minHeight':'500px'
                            },
                            className='refreshing' #SipsTea
                        )
                    ],
                    type="circle",
                )],
                style={
                    'display':'table-cell',
                    'maxWidth':'50%',
                    'minWidth': '600px',
                    'minHeight':'500px'
                },
            ),
            html.Div([
                dcc.Loading(
                    id='host-details-copy',
                    children=[
                        html.Iframe(
                            id='hosts-frame-copy',
                            src='/hosts-describe',
                            style={
                                'display':'table-cell',
                                'width':'100%',
                                'minWidth': '600px',
                                'minHeight':'500px'
                            },
                            className='refreshing' #SipsTea
                        )
                    ],
                    type="circle",
                ),
                ],
                style={
                    'display':'table-cell',
                    'maxWidth':'50%',
                    'minWidth': '600px',
                    'minHeight':'500px'
                },
            ),
        ],
        style={
            'display':'table-row',
            'minHeight':'500px'
        })
    ],
    style={
        'width':'100%',
        'display':'table'
    })
]


