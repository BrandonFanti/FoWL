from scapy.all import *
from scapy.layers.http import *
from scapy import supersocket
from scapy.sessions import DefaultSession
import inspect
import pickle
from datetime import datetime, timedelta
ts = datetime.now

from lazy_logger import Logger_Base 
from misc import wut
from traceback import format_exception

class Unhandled_Scapy_Type(Exception):
    def __init__(self, message, packet, engine, trace=None):
        super().__init__(message)
        self.trace = trace
        self.timestamp = packet[0]
        self.packet=packet[2]
        self.packet_dump=packet[2].show(dump=True)
        self.predominant_layer = self.packet.lastlayer()
        self.source_file_dot_function = __class__.where_am_i()
        self._class_version = 1

    def where_am_i():
        sf = inspect.stack()[3]
        you_are_here = sf.filename+'.'+sf.function
        return you_are_here

    # def __str__(self, logger=None):
    #     return f"Neither the engine({self.engine}), or handler({self.source_file_dot_function}) could interpret type({self.predominant_layer}): \n {self.packet_dump}"

    def __reduce__(self):
        return(Unhandled_Scapy_Type, (message, packet, engine, self.handler))

name = "scapy_handler"
log_file=f"{name}-Sess-{ts()}.log"

logger=Logger_Base(name=name, file_path='log/'+log_file)

#Args is FOWL.py's FOWL_Argument_Parser()
# if args and args.debugging:
logger.enable_debug()
# logger.debug("with debugging!")


def test_get_handler_identity():
    print(where_am_i())


dnstypes = {
    0: "ANY",
    1: "A", 2: "NS", 3: "MD", 4: "MF", 5: "CNAME", 6: "SOA", 7: "MB", 8: "MG",
    9: "MR", 10: "NULL", 11: "WKS", 12: "PTR", 13: "HINFO", 14: "MINFO",
    15: "MX", 16: "TXT", 17: "RP", 18: "AFSDB", 19: "X25", 20: "ISDN",
    21: "RT", 22: "NSAP", 23: "NSAP-PTR", 24: "SIG", 25: "KEY", 26: "PX",
    27: "GPOS", 28: "AAAA", 29: "LOC", 30: "NXT", 31: "EID", 32: "NIMLOC",
    33: "SRV", 34: "ATMA", 35: "NAPTR", 36: "KX", 37: "CERT", 38: "A6",
    39: "DNAME", 40: "SINK", 41: "OPT", 42: "APL", 43: "DS", 44: "SSHFP",
    45: "IPSECKEY", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 49: "DHCID",
    50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA", 53: "SMIMEA", 55: "HIP",
    56: "NINFO", 57: "RKEY", 58: "TALINK", 59: "CDS", 60: "CDNSKEY",
    61: "OPENPGPKEY", 62: "CSYNC", 63: "ZONEMD", 64: "SVCB", 65: "HTTPS",
    99: "SPF", 100: "UINFO", 101: "UID", 102: "GID", 103: "UNSPEC", 104: "NID",
    105: "L32", 106: "L64", 107: "LP", 108: "EUI48", 109: "EUI64", 249: "TKEY",
    250: "TSIG", 256: "URI", 257: "CAA", 258: "AVC", 259: "DOA",
    260: "AMTRELAY", 32768: "TA", 32769: "DLV", 65535: "RESERVED"
}
dnstypes_rl = dict((v,k) for k,v in dnstypes.items())


def handle_dns(packet, db=None) -> None:
    #Yikes.... TODO: Cleanup, if possible, the scapy structure is hard to nav
    #Something I should have done... broken up MDNS and DNS,
    #I will probably want to do this regardless, for DB records
    timestamp, sock, spkt = packet
    logger.debug("handle_dns")
    logger.debug(spkt.show(dump=True))
    host_src = spkt['IP'].src.replace('.','_')
    host_dst = spkt['IP'].src.replace('.','_')
    DNS_OPCODE_NAME = spkt['DNS'].get_field('opcode').i2repr_one(
        spkt,
        spkt['DNS'].opcode
    )

    def parse_record(r, record_into={}):
        new_record = {}
        if hasattr(r, 'type'):
            type_name_field = 'type'
        elif hasattr(r, 'qtype'):
            type_name_field = 'qtype'
        else:
            logger.debug(f"Can't parse record? {r.show(dump=True)}")
            raise Unhandled_Scapy_Type("DNS Parser error", packet, None)

        type_id = getattr(r, type_name_field)

        DNS_RECORD_TYPE = r.get_field(type_name_field).i2repr_one(
            spkt,
            type_id
        )
        logger.debug(f"|\t {DNS_RECORD_TYPE}({type_id}):")
        if  type_name_field == "qtype":
            logger.debug(f"|\t\t{r.qname}")
            new_record['type'] = "query"
        else:
            new_record['type'] = "response"
            new_record['subtype'] = DNS_RECORD_TYPE

            if type_id == dnstypes_rl["SRV"]: 
                answer = (r.target, r.port)
                logger.debug(f"|\t\t{answer}") 
                new_record['result'] = answer
            elif type_id == dnstypes_rl["NSEC"]: 
                answer = (r.rrname, r.nextname)
                logger.debug(f"|\t\t{answer}") 
                new_record['result'] = answer
            elif type_id == dnstypes_rl["TXT"]:
                if type(r.rdata) == list:
                        answer = (r.rrname.decode('utf-8'), '->',\
                            [d.decode('utf-8') for d in r.rdata])
                logger.debug(f"|\t\t{answer}") 
                new_record['result'] = answer
            elif type_id == dnstypes_rl["OPT"]:
                pass #TODO: Not sure? 
            else:
                #TODO: UTF-??? https://knowyourmeme.com/memes/thinking-foot-thinking-holding-cup-foot
                if type(r.rdata) == list:
                        answer = (r.rrname.decode('utf-8'), '->', \
                            '\n'.join([d.decode('utf-8') for d in r.rdata]))
                if type(r.rdata) == str:
                        answer = (r.rrname.decode('utf-8'), '->', r.rdata)
                if type(r.rdata) == bytes:
                        answer = (r.rrname.decode('utf-8'), '->', r.rdata.decode('utf-8'))
                logger.debug(f"|\t\t{answer}") 
                new_record['result'] = answer
        return new_record

    p = spkt['DNS']
    if spkt[DNS].opcode == 0: #QUERY, which can include responses/answers
        if p.ancount+p.arcount == 0:
            for i in range(spkt['DNS'].qdcount):
                db.add_to_key(f"host.{host_src}.DNS.queries", p.qd[i].qname) #Move this, use scapy pkt.dns.answers(queries), or something
            return
        answers = []
        for i in range(spkt['DNS'].qdcount):
            parse_record(p.qd[i])
        for i in range(spkt['DNS'].ancount):
            answers.append(parse_record(spkt['DNS'].an[i]))
        for i in range(spkt['DNS'].arcount):
            answers.append(parse_record(spkt['DNS'].ar[i]))
    #TODO: collect un-answered queries here, to compare properly
        for result in answers:
            db.add_to_key(f"host.{host_dst}.DNS.answers", result) 
        #IE, use scapy pkt.dns.answers(queries), or something

        return
    if spkt[DNS].opcode == 1: #IQUERY
        logger.debug("DNS IQUERY: improve handling?")
    if spkt[DNS].opcode == 2: #STATUS
        logger.debug("DNS STATUS: improve handling?")

    raise Unhandled_Scapy_Type("Unhandled DNS", packet, None)

def handle_udp(packet, db=None) -> None:
    timestamp, sock, spkt = packet
    logger.debug("handle_udp")
    logger.debug(f"sport:{spkt.sport}/dport:{spkt.dport}")
    host_src = spkt['IP'].src.replace('.','_')
    host_dst = spkt['IP'].src.replace('.','_')

    #TODO: REMOVE ME annoying mikrotik in testing
    if spkt.haslayer(Raw) and b'MikroTik' in spkt['Raw'].load:
        return

    if db and spkt.dport == 57621 and b'SpotUdp' in spkt['Raw'].load:
        db.add_to_key(f"host.{host_src}.advertising", "Music-Service: Spotify (SpotUDP)")
        return

    if spkt.haslayer(BOOTP):
        if db and spkt[BOOTP].op == 1: #Request
            db.add_to_key(f"MAC_Seen", spkt[BOOTP].chaddr)
            db.add_to_key(f"host.{host_src}.bootp_request", spkt)
            db.add_to_key(f"host.{host_src}.MAC", spkt[BOOTP].chaddr)
            return
        if db and spkt[BOOTP].op == 2: #Reply
            db.add_to_key(f"host.{host_dst}.bootp_reply", spkt)
            return

    if spkt.haslayer(NTPHeader):
        logger.debug(spkt.show(dump=True))
        if spkt[NTPHeader].mode == 3: #NTP in Client mode
            logger.debug(f"Host time synchronization ({host_src}->{host_dst})")
            if db:
                for k in [l.strip().split('=') if l else None for l in spkt[NTPHeader].show(dump=True).split('\n')[1:]]:
                    if not k or not len(k)==2: continue
                    k,v=k[0].strip(),k[1].strip()
                    db.set_key(f"host.{host_src}.ntp_client.{k}",v)
            #db.save()
            return
        if spkt[NTPHeader].mode == 4: #NTP in Server mode
            logger.debug(f"Host time synchronization ({host_src}->{host_dst})")
            if db:
                for k in [l.strip().split('=') if l else None for l in spkt[NTPHeader].show(dump=True).split('\n')[1:]]:
                    if not k or not len(k)==2: continue
                    k,v=k[0].strip(),k[1].strip()
                    db.set_key(f"host.{host_src}.ntp_server.{k}",v)
                #db.save()
            return
        raise Unhandled_Scapy_Type(f"Unhandled NTP({spkt[NTPHeader].mode})", packet, None)

    if db and spkt.dport == 1900 and len(spkt['Raw'].load) < 2000:
        logger.info(f"Recording WFADevice: {host_src}")
        if b'NOTIFY * HTTP/1.1' in spkt['Raw'].load:
            notify_str = spkt['Raw'].load.decode('unicode_escape')
            logger.info(notify_str)
            notify_lines = [line.strip() for line in notify_str.split('\n')]
            notify_lines.remove("")
            db.add_to_key(f"host.{host_src}.SSDP.advertising", notify_lines)
        if b'M-SEARCH * HTTP/1.1' in spkt['Raw'].load:
            m_search = spkt['Raw'].load.decode('unicode_escape')
            logger.info(m_search)
            m_search_lines = [line.strip() for line in m_search.split('\n')]
            m_search_lines.remove("")
            db.add_to_key(f"host.{host_src}.SSDP.searching", m_search_lines)
            #db.save()
        return True

    if spkt.haslayer(DNS):
        handle_dns(packet, db=db)
        return True


    if spkt.dport in [137,138,139]:
        if hasattr(spkt, 'Raw'):
            if spkt.haslayer(NetBIOSNameField):
                print(hex(spkt.Raw))
            if spkt.haslayer(NBTDatagram):
                print(hex(spkt.Raw))
        raise Unhandled_Scapy_Type("Unhandled NetBIOSNameField/NBTDatagram/XX", packet, None)

    logger.debug("handle_udp: unhandled UDP type...")
    logger.debug(spkt)
    logger.debug(spkt.show(dump=True))
    raise Unhandled_Scapy_Type(f"Unhandled UDP(->{spkt.sport}->{spkt.dport})", packet, None)


def handle_http(packet):
    timestamp, sock, spkt = packet
    logger.debug("handle_http")

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
    logger.debug(f"Forged HTTP response packet: {response.show2(dump=True)}")
    sock.send(response)
    return

def handle_tcp(packet, db=None) -> None:
    timestamp, sock, spkt = packet
    #logger.debug("handle_tcp")
    #logger.debug(f"sport:{spkt.sport}/dport:{spkt.dport}")
    host_src = spkt['IP'].src
    khost_src = host_src.replace('.','_')
    host_dst = spkt['IP'].dst
    khost_dst = host_dst.replace('.','_')


    # Don't manipulate any packets *not containing* SYN, RST
    if all(i in spkt['TCP'].flags for i in ['A']):
        db.add_to_key(f"host.{khost_src}.active_tcp_connection", f"({host_dst}, {spkt.dport})")
        db.add_to_key(f"host.{khost_dst}.active_tcp_connection", f"({host_src}, {spkt.sport})")
        #db.save()

    if not any(i in spkt['TCP'].flags for i in ['S', 'R']): return

    # Record new connection being established
    if all(i in spkt['TCP'].flags for i in ['S', 'A']): 
        db.add_to_key(f"host.{khost_src}.tcp_ACKed", (host_dst, spkt.dport))

    if spkt['TCP'].flags == "S":
        db.add_to_key(f"host.{khost_src}.tcp_probed", (host_dst, spkt.dport))
        #db.save()

    #This is TOTALLY arbitrary, I know, prone to false positives
    if spkt.sport in (59090,60000) and spkt.dport == 8000:
        #But TWICE in the last few hours, I've seen exactly this sport try to hit port 8000
        db.add_to_key("Probable_Scanner", spkt[IP].src)
        return

    if spkt.dport == 443 or spkt.sport == 443:
        raise Unhandled_Scapy_Type("Unhandled TCP - a scraper request?", packet, None)

    if spkt.dport == 80:
        if spkt.haslayer(HTTP):
            handle_http(packet)

        if spkt['TCP'].flags == "S" and \
        not spkt.haslayer(HTTPResponse):
            logger.debug(f"Spoofing response for this: {spkt.show(dump=True)}")

            try:
                logger.debug(f"Spoofing response from {spkt.dst} to {spkt.src}")
                if spkt.haslayer('Raw'):
                    plen = len(spkt['Raw'].load) 
                else: plen = 0
                logger.debug(plen)


                response = IP(src=spkt.dst, dst=spkt.src)\
                    / TCP(
                            sport=spkt.dport, dport=spkt.sport, flags="SA",
                            seq=0, ack=spkt.seq+1,
                        )

            except Exception as e:
                raise Unhandled_Scapy_Type("Unhandled TCP - response could not be generated", packet, None)

            logger.debug(f"Spoofing response: {response.show2(dump=True)}")
            sock.send(
                response
            )
        return

    if spkt['TCP'].flags == "FA":
        response = IP(src=spkt.dst, dst=spkt.src)\
            / TCP(
                    sport=spkt.dport, dport=spkt.sport, flags="A",
                    seq=0, ack=spkt.seq+1,
                )

        return

    logger.debug("handle_tcp: unhandled TCP type...")
    logger.debug(spkt)
    logger.debug(spkt.show(dump=True))


    raise Unhandled_Scapy_Type("Unhandled TCP", packet, None)


def handle_ip(packet, db=None, logger=None) -> None:
    timestamp, sock, spkt = packet
    if spkt.version == '4':
        logger.debug("IPv4")
    if spkt.version == '6':
        logger.debug("IPv6")
    host_src = spkt['IP'].src.replace('.','_')
    host_dst = spkt['IP'].src.replace('.','_')

    #TODO: While it has great potential value, IGMP seems...
    #     -----------------------------------------------------------------------------------------------         #

    if spkt.proto == 2:
        return
        raise Unhandled_Scapy_Type("Unhandled IGMP", packet, None)
        #What is 
        """
  src       = 192.168.1.218
  dst       = 224.0.0.22
  \options   \
   |###[ IP Option Router Alert ]### 
   |  copy_flag = 1
   |  optclass  = control
   |  option    = router_alert
   |  length    = 4
   |  alert     = router_shall_examine_packet
###[ Raw ]### 
     load      = '"\x00\\xf9\x02\x00\x00\x00\x01\x04\x00\x00\x00\\xe0\x00\x00\\xfb'
###[ Padding ]### 
        load      = '\x00\x00\x00\x00\x00\x00'
"""
    #     -----------------------------------------------------------------------------------------------         #
    #TODO: funky, in my network RN at least. Maybe read the actual RFC?

    if spkt.haslayer(UDP):
        return handle_udp(packet, db=db)
    if spkt.haslayer(TCP):
        if db:
            db.add_to_key("IP_Seen", spkt[IP].src)
            db.add_to_key("IP_Seen", spkt[IP].dst)
            if spkt.haslayer(Ether):
                #TODO: Reconsider these for poison detection
                db.add_to_key(f"MAC2IP.{spkt[Ether].src}", spkt[IP].src)
                db.add_to_key(f"MAC2IP.{spkt[Ether].dst}", spkt[IP].dst)
                db.add_to_key(f"host.{host_src}.MAC.src", spkt[Ether].src)
                db.add_to_key(f"host.{host_dst}.MAC.dst", spkt[Ether].dst)
            #db.save()
        return handle_tcp(packet, db=db)

    if spkt.haslayer(ICMP):
        host_src = spkt['IP'].src.replace('.','_')
        host_dst = spkt['IP'].dst
        if spkt[ICMP].type == 9: #router-advertisement
            db.add_to_key(f"host.{host_src}.identifies_as_router", True)
            #db.save()
            return
        if spkt[ICMP].type == 8:
            logger.debug(f"Ping! (RQST) {host_src}->{host_dst}")
            if spkt.haslayer(Ether): #ping request
                db.add_to_key(f"host.{host_src}.MAC.src", spkt[Ether].src)
                db.add_to_key(f"host.{host_src}.MAC.dst", spkt[Ether].dst)
            db.add_to_key(f"host.{host_src}.pings", host_dst)
            #db.save()
            return 
        if spkt[ICMP].type == 0:
            logger.debug(f"Ping! (REPLY) {host_src}->{host_dst}")
            if spkt.haslayer(Ether): #ping reply
                db.add_to_key(f"host.{host_src}.MAC.src", spkt[Ether].src)
                db.add_to_key(f"host.{host_src}.MAC.dst", spkt[Ether].dst)
            db.add_to_key(f"host.{host_src}.ping_replied", host_dst)
            return 

        raise Unhandled_Scapy_Type(f"Unhandled ICMP({spkt[ICMP].type})", packet, None)

    logger.debug("handle_ip: unhandled IP type...")
    logger.debug(spkt)
    logger.debug(spkt.show(dump=True))
    raise Unhandled_Scapy_Type("Unhandled IP", packet, None)


def handle(pkt, *args, logger=None, **kwargs):
    return
    timestamp, sock, spkt = pkt

    if 'database' in kwargs: database = kwargs.pop('database', None)
    # logger=Logger_Base(name="scapy_handler")

    #TODO: remove me! Interesting things inside.
    #if spkt.dst == '127.0.0.1': return

    # if spkt.dst != '192.168.1.218': return
    # if not spkt.haslayer(ICMP): return
    # if not spkt.haslayer(IP): return
    # if not spkt.haslayer(NTPHeader): return
    # if not spkt.proto==2: return

    try:
        if database and spkt.haslayer(Ether):
            database.add_to_key("MAC_Seen", spkt.src)
            database.add_to_key("MAC_Seen", spkt.dst)
            if spkt.haslayer(IP):
                host_src = spkt['IP'].src.replace('.','_')
                database.add_to_key(f"MAC2IP.{spkt[Ether].src}", spkt[IP].src)
                database.add_to_key(f"host.{host_src}.MAC.src", spkt[Ether].src)
                database.add_to_key(f"host.{host_src}.MAC.dst", spkt[Ether].dst)

        if spkt.haslayer(IP):
            return handle_ip(pkt, db=database, logger=logger)

        if spkt.haslayer(EAPOL):
            if logger:
                logger.info("YES EAPOL - HANDLE THIS BETTER")
            with open(f"The_Pickle_Jar/EAPOL/{spkt}.sp", 'wb') as f:
                f.write(pickle.dumps(pkt))
            return True

        #Undefined handling
        # if not IP in spkt \
        #     and not IPv6 in spkt\
        #     and not ARP in spkt:
        #     if logger:
        #         logger.debug(f"Name: {spkt.name}")
        #         logger.debug(f"layers: {spkt.layers}")
        #         logger.debug(f"aliases: {spkt.aliastypes}")
        #         logger.debug(f"What is this? {spkt}")
        #         logger.debug(spkt.show(dump=True))
        #         wut(spkt)
    except Exception as e:
        e.trace = "".join(format_exception(type(e), e, e.__traceback__))
        raise e
