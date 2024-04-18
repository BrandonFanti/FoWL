from scapy.all import TCP as scapy_TCP
from datetime import datetime

class TCP(scapy_TCP):

    def __init__(self, initial_packet, timestamp, originating_socket):
        self.init_packet = initial_packet
        self.packet_list = [initial_packet]
        self.latest_packet = None
        self.connection_start = timestamp

    @staticmethod
    def factory(socket, p: scapy_TCP, session_begins=datetime.now()):
        return __class__.__init__(p, session_begins, socket)
