from sys import argv, path
if not 'src' in path:
    path.append('src')

import plotly.graph_objects as go
import plotly.io as pio
import networkx as nx

from datetime import datetime
from time import sleep
import numpy as np
import json

import dash
from dash import dcc,html,clientside_callback,ClientsideFunction,State
from dash_extensions import WebSocket
from dash_extensions.enrich import DashProxy, Output, Input
import dash_bootstrap_components as dbc

from visualization.template import page_container,plotly_template_dark,external_stylesheets


dapp = dash.Dash(name='Le Dash', title='Le Dash', 
    use_pages=True, 
    pages_folder="src/visualization/dash_app/", 
    assets_folder="src/visualization/assets/",
    external_stylesheets=external_stylesheets,
    suppress_callback_exceptions=True
) #SET ``
dapp.layout = html.Div(
    [
        WebSocket(id="ws", url="ws://127.0.0.1:8052/root"),
        page_container
    ],
    style={
        'overflow': 'scroll',
        'width':'100vw',
        'height':'100vh'
    }
)

dapp.clientside_callback(
    """
    (switchOn) => {
        document.documentElement.setAttribute("data-bs-theme", switchOn ? "light" : "dark"); 
        return window.dash_clientside.no_update
    }
    """,
    Output("switch", "id"),
    Input("switch", "value"),
)
# print(dash.page_registry.values())


dapp.clientside_callback(
    "function(msg){try{d=atob(JSON.parse(msg.data).e);console.log('Running:');console.log(d);eval(d)}catch(error){console.log(error)}}",
    Input("ws", "message"),
    # force_no_output=True,
    prevent_initial_call=True,
)



dapp.run_server(host="127.0.0.1", port="8051",use_reloader=True,
    debug=True,
    # debug=False
)




