from datetime import datetime
import plotly.graph_objects as go
import plotly.io as pio
import networkx as nx
import numpy as np
import json

import ipaddress

from dash import dcc,html,get_asset_url

from visualization.template import plotly_template_dark,external_stylesheets

class parser:
    def __init__(self, *args, **kwargs):
        pass

    @staticmethod
    def consume(data):
        g = nx.MultiDiGraph()

        #g.add_node(__class__.parse_nodes_by_IPs(data))
        #g.add_node(__class__.parse_nodes_by_MACs(data))
        #g.add_node(__class__.parse_nodes_by_IPs(data))

        return g

    @staticmethod
    def parse_nodes_by_MAC2IPs(data):
        nodes=[]
        edges=[]

        #Make nodes
        for mac in data["MAC2IP"].keys():
            for ip in data["MAC2IP"][mac]:
                ip = ip.replace('_','.')
                nodes.append(ip+'/'+mac)

        #Make edges/links
        for ip in data['host'].keys():
            ip_f = ip.replace('_','.')
            if "MAC" in data['host'][ip].keys():
                # print(f"    {data['host'][ip]['MAC']}")
                if 'src' in data['host'][ip]['MAC'] \
                    and 'dst' in data['host'][ip]['MAC'].keys():
                    src = ip_f+'/'+data['host'][ip]['MAC']['src'][0]
                    for mi,dst_mac in enumerate(data['host'][ip]['MAC']['dst']):
                        if not dst_mac in data["MAC2IP"]: continue
                        dst = data["MAC2IP"][dst_mac][0]+'/'+dst_mac
                        # print(f"        {src}->{dst}")
                        edges.append((src, dst))
                        edges.append((dst, src))
            # else: continue
            # for mac in data['MAC2IP'].keys():
            #     if any(ip_mac_src) == mac[0]: #TODO: Remove [0]
            #         edges.append((mac[0], ip_mac_src))#TODO: Remove [0]
        return (nodes, edges)


    @staticmethod
    def parse_nodes_by_IPs(data):
        if not data['origin_host_interfaces']: return
        networks = [ipaddress.ip_network(data['origin_host_interfaces'][interface]['cidr']) for interface in data['origin_host_interfaces']]

        nodes=[]
        edges=[]

        def is_ip_in_scope(ip:str):
                return any(ipaddress.ip_address(ip) in \
                    network for network in networks)


        #Make nodes
        for mac in data["MAC2IP"].keys():
            for ip in data["MAC2IP"][mac]:
                ip = ip.replace('_','.')
                if not is_ip_in_scope(ip):
                    continue
                nodes.append(ip+'/'+mac)

        #Make edges/links
        for ip in data['host'].keys():
            ip_f = ip.replace('_','.')
            if not is_ip_in_scope(ip_f):
                continue
            if "MAC" in data['host'][ip].keys():
                # print(f"    {data['host'][ip]['MAC']}")
                if 'src' in data['host'][ip]['MAC'] \
                    and 'dst' in data['host'][ip]['MAC'].keys():
                    src = ip_f+'/'+data['host'][ip]['MAC']['src'][0]
                    for mi,dst_mac in enumerate(data['host'][ip]['MAC']['dst']):
                        if not dst_mac in data["MAC2IP"]: continue
                        if not is_ip_in_scope(data["MAC2IP"][dst_mac][0]): continue
                        dst = data["MAC2IP"][dst_mac][0]+'/'+dst_mac
                        # print(f"        {src}->{dst}")
                        edges.append((src, dst))
                        edges.append((dst, src))
            # else: continue
            # for mac in data['MAC2IP'].keys():
            #     if any(ip_mac_src) == mac[0]: #TODO: Remove [0]
            #         edges.append((mac[0], ip_mac_src))#TODO: Remove [0]
        return (nodes, edges)


    @staticmethod
    def parse_nodes_by_MACs(json):
        pass


class data_visualizer():
    def __init__(self, *args, **kwargs):
        pass

    @staticmethod
    def cannot_visualize(img_percent="50%"):
        return html.Img(src=get_asset_url("shrug.jpg"), style={'height':img_percent,'width':img_percent})


    @staticmethod
    def plot_multidi(G):
        pass

    @staticmethod
    def plot(G, title='UNDEFINED'):

        pos = nx.spring_layout(G)

        dic = {}

        #nx.spring returned a node:position dictionary
        node_x = []
        node_y = []
        for node in pos.keys():
            dic[node] = {}
            dic[node]['pos'] = {}
            x, y = pos[node]
            dic[node]['pos'] = pos[node]
            # print(f"Node({node}) pos x({x}),y({y})")
            node_x.append(x)
            node_y.append(y)

        edge_x = []
        edge_y = []
        for edge in G.edges():
            # print(edge)
            x0, y0 = dic[edge[0]]['pos']
            x1, y1 = dic[edge[1]]['pos']
            # print(f"Edge Pos\tx0({x0}),y0({y0})\n\tx1({x1}),y1({y1})")
            edge_x.append(x0)
            edge_x.append(x1)
            edge_x.append(None)
            edge_y.append(y0)
            edge_y.append(y1)
            edge_y.append(None)

        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5, color='#888'),
            hoverinfo='none',
            mode='lines')


        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers',
            hoverinfo='text',
            marker=dict(
                showscale=True,
                # colorscale options
                #'Greys' | 'YlGnBu' | 'Greens' | 'YlOrRd' | 'Bluered' | 'RdBu' |
                #'Reds' | 'Blues' | 'Picnic' | 'Rainbow' | 'Portland' | 'Jet' |
                #'Hot' | 'Blackbody' | 'Earth' | 'Electric' | 'Viridis' |
                colorscale='Blackbody',
                reversescale=True,
                color=[],
                size=10,
                colorbar=dict(
                    thickness=15,
                    title='Node Connections',
                    xanchor='right',
                    titleside='right'
                ),
                line_width=2)
        )

        node_adjacencies = []
        node_text = []
        nodes_list = np.array(list(G.nodes()))
        # print(nodes_list)
        # exit()
        for node, adjacencies in enumerate(G.adjacency()):
            ip_txt,mac_txt = nodes_list[node].split('/')
            mac_txt = f"MAC: {mac_txt}<br>"
            ip_txt = f"IP: {ip_txt}<br>"
            num_conn_txt = f"# of connections: {len(adjacencies[1])}"
            txt=mac_txt+ip_txt+num_conn_txt
            node_text.append(txt)
            node_adjacencies.append(len(adjacencies[1]))

        node_trace.marker.color = node_adjacencies
        node_trace.text = node_text

        fig = go.Figure(data=[edge_trace, node_trace],
                    layout=go.Layout(
                        title=f"{title} @({datetime.now()})",
                        titlefont_size=16,
                        showlegend=False,
                        hovermode='closest',
                        margin=dict(b=20,l=5,r=5,t=40),
                        annotations=[ dict(
                            showarrow=False,
                            xref="paper", yref="paper",
                            x=0.005, y=-0.002 ) ],
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        template=plotly_template_dark,
                    ),
        )
        return fig

    @staticmethod
    def sample_whole_plot():
        G = nx.random_geometric_graph(200, 0.125)

        edge_x = []
        edge_y = []
        for edge in G.edges():
            x0, y0 = G.nodes[edge[0]]['pos']
            x1, y1 = G.nodes[edge[1]]['pos']
            # print(f"Edge Pos\tx0({x0}),y0({y0})\n\tx1({x1}),y1({y1})")
            edge_x.append(x0)
            edge_x.append(x1)
            edge_x.append(None)
            edge_y.append(y0)
            edge_y.append(y1)
            edge_y.append(None)

        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=0.5, color='#888'),
            hoverinfo='none',
            mode='lines')

        node_x = []
        node_y = []
        for node in G.nodes():
            x, y = G.nodes[node]['pos']
            # print(f"Node pos x({x}),y({y})")
            node_x.append(x)
            node_y.append(y)

        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers',
            hoverinfo='text',
            marker=dict(
                showscale=True,
                # colorscale options
                #'Greys' | 'YlGnBu' | 'Greens' | 'YlOrRd' | 'Bluered' | 'RdBu' |
                #'Reds' | 'Blues' | 'Picnic' | 'Rainbow' | 'Portland' | 'Jet' |
                #'Hot' | 'Blackbody' | 'Earth' | 'Electric' | 'Viridis' |
                colorscale='YlGnBu',
                reversescale=True,
                color=[],
                size=10,
                colorbar=dict(
                    thickness=15,
                    title='Node Connections',
                    xanchor='left',
                    titleside='right'
                ),
                line_width=2))

        node_adjacencies = []
        node_text = []
        for node, adjacencies in enumerate(G.adjacency()):
            node_adjacencies.append(len(adjacencies[1]))
            node_text.append('# of connections: '+str(len(adjacencies[1])))

        node_trace.marker.color = node_adjacencies
        node_trace.text = node_text


        fig = go.Figure(data=[edge_trace, node_trace],
            layout=go.Layout(
                title='Network graph of MAC to MAC comms',
                titlefont_size=16,
                showlegend=False,
                hovermode='closest',
                margin=dict(b=20,l=5,r=5,t=40),
                annotations=[ dict(
                    text="Python code: <a href='https://plotly.com/python/network-graphs/'> https://plotly.com/python/network-graphs/</a>",
                    showarrow=False,
                    xref="paper", yref="paper",
                    x=0.005, y=-0.002 ) ],
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                template=plotly_template_dark,
            )
        )
        return fig


    @staticmethod
    def generate_new_graph_DIV_bytes(show=False):
        x = __class__.generate_new_graph_DashDIV(show=show)
        x=fig.to_html(full_html=False)
        return str(x)

    @staticmethod
    def generate_new_graph_DashDIV(parser_func=parser.parse_nodes_by_MAC2IPs, title="UNDEFINED", show=False) -> dcc.Graph:
        source_file="data/RAM_CACHE.JSON"
        try:
            with open(source_file, 'r') as f:
                data = json.loads(f.read())
            g = parser.consume(data)
            parsed = parser_func(data)
        except Exception as e:
            print(f"File not found: {source_file}")
            parsed=None
        if not parsed:
            return html.Div([
                html.H4("Source data could not generate this: PCAP, or interface not configured?"),
                __class__.cannot_visualize(img_percent="40%")
            ])
        nodes,edges = parsed
        g.add_nodes_from(nodes)
        g.add_edges_from(edges)
        fig = data_visualizer.plot(g, title=title)
        if show: fig.show()
        return dcc.Graph(id='mac-graph-root', figure=fig, responsive=True, animate=False)

    @staticmethod
    def generate_hosts_list(show=False) -> []:
        source_file="data/RAM_CACHE.JSON"
        try:
            with open(source_file, 'r') as f:
                data = json.loads(f.read())
                return [(host,data['host'][host]) for host in data['host'].keys()]
        except:
            pass

    async def MAC_Graph_old():
        data_src = "data/RAM_CACHE.JSON"
        last_size = 0
        await websocket.accept()
        while True:
            while stat(data_src).st_size != last_size:
                last_size = stat(data_src).st_size
                with open(data_src, 'r') as f:
                    await websocket.send(
                        __class__.generate_new_graph_DIV_bytes()
                    )
            await asyncio.sleep(2) #Maximum update interval
