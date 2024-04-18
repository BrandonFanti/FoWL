
#TODO: Remove this - Hack until I get poetry setup
from lazy_logger import Logger_Base
name = "my_custom_handler"
log_file=f"log/{name}.log"
logger=Logger_Base(name=name, file_path=log_file)
logger.info("logger started")


#from default scapy_handlers -> Hackneyed response
def handle(timestamp, src_socket, pkt):
    logger.debug("my_custom_handler called!")
    logger.debug(timestamp)
    logger.debug(src_socket)
    logger.debug(pkt)

def nullal():
    response = IP(src=spkt.dst, dst=spkt.src)\
    / TCP(
        sport=spkt.dport, dport=spkt.sport, flags="A",
        seq=1, ack=spkt.seq+1,
    )
    sock.send(response)

    response = IP(src=spkt.dst, dst=spkt.src)\
            / TCP(
                sport=spkt.dport, dport=spkt.sport, flags="PAF",
                seq=1, ack=spkt.seq+1,
            )
    response = response / HTTP() / HTTPResponse(Server="Hackneyed") / "<html><Title>Lame</Title>Hi</html>"
    logger.info(f"Forged HTTP response packet: {response.show2(dump=True)}")
    sock.send(response)