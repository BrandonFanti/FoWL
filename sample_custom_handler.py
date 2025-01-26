
#TODO: Remove this - Hack until I get poetry setup
from lazy_logger.my_logger import Logger_Base
name = "my_custom_handler"
log_file=f"log/{name}.log"
logger=Logger_Base(name=name, file_path=log_file)
logger.info("logger started")
logger.enable_debug()
# logger.set_level(logger.INFO)

from iscapy.scapy_handler import Unhandled_Scapy_Type
from datetime import datetime
ts = datetime.now
from scapy.all import *
from scapy.layers.http import *

import ipaddress

def record_ban(ts, sock, spkt, database_cli=None):
    host_src = spkt['IP'].src.replace('.','_')
    query_key = f"host.{host_src}.banned"

    banned = None
    if not database_cli:
        logger.warn(f"No database client! Can't record ban status")
    else:
        banned = database_cli.get(query_key)
        if not banned:
            logger.colorize(f"Recorded ban for host {host_src}", color='Red')
            database_cli.set_key(query_key, True)

def handle_http(spkt, sock):
    response = IP(src=spkt[IP].dst, dst=spkt[IP].src)\
    / TCP(
        sport=spkt.dport, dport=spkt.sport, flags="A",
        seq=1, ack=spkt.seq+1,
    )
    send(response, verbose=False, socket=sock)


    response = IP(src=spkt[IP].dst, dst=spkt[IP].src)\
            / TCP(
                sport=spkt.dport, dport=spkt.sport, flags="PAF",
                seq=1, ack=spkt.seq+1,
            )
    response = response / HTTP() / HTTPResponse(Server="Hackneyed") /\
"""<!DOCTYPE html> 
<html>
<Title>Lame</Title>
<body style="background-color: #111111 ; color: #FC2A2A">
<center>
<p style="font-size:72px">Hackneyed!</p>
<img style="width:100%; height:100%" src='https://github.com/BrandonFanti/FoWL/raw/release/src/visualization/assets/fowl.png'>
<center>
<body>
</html>"""



    logger.debug(f"Forged HTTP response to host {spkt[IP].src}!")# packet: {response.show2(dump=True)}")
    send(response, verbose=False, socket=sock)
    return

#streamlined scapy_handlers -> Hackneyed demo response
def handle(timestamp, sock, spkt, **kwargs):
    # logger.info("my_custom_handler called!")

    #TODO: remove me! Interesting things inside.
    if spkt.dst == '127.0.0.1': return

    if not ipaddress.IPv4Address(spkt.src) in ipaddress.IPv4Network('192.168.0.0/16'):
        return

    if not spkt.haslayer(IP):
        logger.debug(f"Packet has no IPs, skipping")
        return

    # logger.debug(spkt.show2(dump=True))

    #Handle HTTP requests
    if spkt.dport == 80 and spkt.haslayer(HTTP):
        handle_http(spkt, sock)

    if spkt.haslayer(IP):
        # logger.info(f"Handling IP traffic from {spkt[IP].src} to {spkt[IP].dst}")
        # logger.debug(f"(RX to handler latency: {logger.timedelta_fmt(ts()-timestamp)})")

        if spkt.haslayer(TCP):
            # logger.debug("Handling TCP")

            if spkt.dport == 80: #Handle TCP handshake, for what should become a client HTTP requests

                #If the connection is starting
                if spkt['TCP'].flags == "S" and not spkt.haslayer(HTTPResponse):

                    response = IP(src=spkt[IP].dst, dst=spkt[IP].src)\
                        / TCP(
                                sport=spkt.dport, dport=spkt.sport, flags="SA",
                                seq=0, ack=spkt.seq+1,
                            )
                    send(response, verbose=False, socket=sock)

                return

                if spkt['TCP'].flags == "FA":
                    response = IP(src=spkt[IP].dst, dst=spkt[IP].src)\
                        / TCP(
                                sport=spkt.dport, dport=spkt.sport, flags="A",
                                seq=0, ack=spkt.seq+1,
                            )

                    send(response, verbose=False, socket=sock)

                    return