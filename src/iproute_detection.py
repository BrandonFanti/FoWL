import pprint
from socket import AF_INET
from pyroute2 import IPDB, IPRoute
ipdb=IPDB()
interfaces = ipdb.by_name.keys()
ipr=IPRoute()
interface_addrs = [(i,ipr.get_addr(label=i)) for i in interfaces]
routes = ipr.get_routes()

def get_cidr_notated_route(addr):
    cidr = addr['prefixlen']
    addr = addr.get_attr('IFA_ADDRESS')
    addr = ".".join(addr.split(".")[0:-1]) #Cut out the last octet
    addr = addr+'.0/'
    return addr+str(cidr)

def get_interface_info(**kwargs):
    disable_loopback = kwargs.pop('loopback', True)
    debug = kwargs.pop('debug', None)
    logger = kwargs.pop('logger', None)
    if not logger:
        from lazy_logger import Logger_Base
        logger=Logger_Base(name=__name__)
        if debug: logger.enable_debug()

    # [logger.debug(f"{pprint.pformat(addrs)}") for name,addrs in interface_addrs]
    # logger.debug(f"{pprint.pformat(ipr.get_routes(family=AF_INET))}")
    # logger.debug(f"{pprint.pformat(ipr.get_links())}")

    link_macs = {}
    link_slaves={}
    link_masters={}
    links = ipr.get_links()
    for name in interfaces:
        for link in links:
            if link.get_attr('IFLA_IFNAME') == name:
                # logger.debug(name)
                if link.get_attr('IFLA_LINKINFO'): 
                    if link.get_attr('IFLA_LINKINFO').get_attr('IFLA_INFO_SLAVE_KIND'):
                        slave_to = link.get_attr('IFLA_LINKINFO').get_attr('IFLA_INFO_SLAVE_DATA').get_attr('IFLA_BRPORT_BRIDGE_ID')['addr']
                        link_slaves[name] = {}
                        link_slaves[name]['slaved_to'] = slave_to
                        link_slaves[name]['mac'] = link.get_attr('IFLA_ADDRESS')
                    elif link.get_attr('IFLA_LINKINFO').get_attr('IFLA_INFO_KIND') == 'bridge':
                        master=link.get_attr('IFLA_LINKINFO').get_attr('IFLA_INFO_DATA').get_attr('IFLA_BR_BRIDGE_ID')['addr']
                        link_masters[name] = {}
                        link_masters[name]['mac'] = master
                    link_macs[name] = {}
                    link_macs[name]['mac'] = link.get_attr('IFLA_ADDRESS')
                else:
                    link_macs[name] = {}
                    link_macs[name]['mac'] = link.get_attr('IFLA_ADDRESS')
                logger.debug(f"LINK: {pprint.pformat(link)}")
                # else: logger.debug(f" {pprint.pformat(link.get_attr('IFLA_LINKINFO'))}")

    logger.debug(f"LINK SLAVES: {pprint.pformat(link_slaves)}")
    logger.debug(f"LINK MASTERS: {pprint.pformat(link_masters)}")
    logger.debug(f"LINKS: {pprint.pformat(link_macs)}")

    for name in link_slaves.keys():
        # logger.debug(f"Link {name} slaved to {link_slaves[name]}")
        for mname in link_masters.keys():
            if name in link_slaves.keys():
                logger.debug(link_slaves[name])
            if link_masters[mname]['mac'] == link_slaves[name]['slaved_to']:
                # logger.debug(f" AKA link name: {mname}")
                for iname,addr in interface_addrs:
                    if mname == iname:
                        # logger.debug(f"   w ADDRS: {addr}")
                        for x,y in interface_addrs:
                            if x == name: interface_addrs.remove((x,y))
                        interface_addrs.append((name, addr))
                        # logger.debug(f"Replaced addr {name} with: {addr}")

    interface_repr = {}
    for name,addr in interface_addrs:
        logger.debug('*'*100)
        logger.debug(f"Reviewing interface {name}")
        if addr == (): continue
        if name in link_masters: continue #Link masters are resolved under their slaves

        addr_rec = addr[0]
        addr_v4 = addr_rec.get_attr('IFA_ADDRESS')
        if addr_v4 == '127.0.0.1' and disable_loopback: continue

        interface_repr[name] = {}
        if name in link_slaves: 
            interface_repr[name]['slave_to'] = addr_rec.get_attr('IFA_LABEL')
            interface_repr[name]['mac'] = link_slaves[name]['mac']
        interface_repr[name]['mac'] = link_macs[name]['mac']
        interface_repr[name]['addr_v4'] = addr_v4
        interface_repr[name]['cidr'] = get_cidr_notated_route(addr_rec)

        logger.debug('*'*100)
        logger.debug(f"Name {name}:")
        logger.debug(f"\tMAC:   {interface_repr[name]['mac']}")
        logger.debug(f"\tSource:   {interface_repr[name]['addr_v4']}")
        logger.debug(f"\tCIDR net: {interface_repr[name]['cidr']}")
        logger.debug('*'*100)

    logger.debug('*'*100)
    logger.debug(f"Final interface repr: \n {pprint.pformat(interface_repr)}")
    logger.debug('*'*100)
    return interface_repr