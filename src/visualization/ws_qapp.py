from sys import argv, path
if not 'src' in path:
    path.append('src')
print(path)

import asyncio
from quart import websocket, Quart
from os import stat
from os.path import exists as path_exists, isfile
from visualization import parser 
from time import sleep
import json
from base64 import b64encode

qapp = Quart(__name__)


@qapp.websocket("/root")
async def root():
    await websocket.accept()
    while True:
        await asyncio.sleep(30)


@qapp.websocket("/MAC_Graph_auto")
async def MAC_Graph():
    data_src = "data/RAM_CACHE.JSON"
    last_size = 0
    await websocket.accept()
    # await asyncio.sleep(5)
    while True:
        if last_size == 0: last_size = stat(data_src).st_size
        if path_exists(data_src) and isfile(data_src) and stat(data_src).st_size != last_size:
            last_size = stat(data_src).st_size
            await websocket.send(json.dumps({'e': str(b64encode( #I AM ABOVE "THE LAW": 
                '''
                ss=['/mac-graph','hosts-describe'];
                p=document.getElementById('graph');
                console.log(p);
                if( p.len != 0){
                    new_es=[];
                    Array.from(document.getElementsByClassName("refreshing")).forEach((e)=>{
                        console.log('refreshing : ');
                        console.log(e);
                        e.src = '';
                        new_es.push(e.cloneNode(true));
                        e.remove();
                    });
                    console.log(new_es);
                    for (i=0;i<new_es.length;i++) {
                        new_es[i].src = ss[i];
                        console.log(new_es[i]);
                        p.appendChild(new_es[i]);
                    }
                }
                '''.replace('\n','').replace(' ','').encode('utf-8')))[2:-1]
            }))#No but honestly, this here is quite possibly the most fragile code that I've ever written

        await asyncio.sleep(2) #Maximum update interval

@qapp.endpoint("/MAC_Graph")
def MAC_Graph():
    return parser.generate_new_graph_DIV()

qapp.run(host="127.0.0.1", port=8052)
