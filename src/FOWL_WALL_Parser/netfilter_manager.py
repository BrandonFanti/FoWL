import nftables
from pyroute2 import NDB, IPRoute, netns

from lazy_logger.my_logger import Logger_Base
from datetime import datetime, timedelta
ts = datetime.now


# Interesting... Stateless you say!?

# table inet raw {
# 	chain prerouting {
# 		type filter hook prerouting priority raw; policy accept;

# https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)#Stateless_NAT


class netfilter_manager:
    name = __name__
    log_file=f"log/{name}-Sess-{ts()}.log"
    logger=Logger_Base(name=name, file_path=log_file, log_level=20) #level 20 is info
    # logger.enable_debug()
    netlink_ns = 'ns_FoWL'
    veth_pair = ("FoWL0", "FoWL1")

    def __init__(self, rule_list=[]):
        self._nft = nftables.Nftables()
        self._nft.set_handle_output(True)
        self._handle_lookup_map = {}
        self.ignore_list = []
        self.fowlin_host_list = []

        # with IPRoute() as ipr:
        #     self.iFoWL_link = ipr.link('add', ifname='FoWL', kind='veth')


        netns.create(self.netlink_ns)

        self._ndb = NDB()
        self._ndb.sources.add(netns=self.netlink_ns)

        self.setup_veth()
        self.insert_rule("tcp flags & (rst) != 0", chain="OUTPUT", action='drop') #Let FoWL take care of this one, kernel...


    def setup_veth(self):
        ipr = IPRoute()
        self.ipr = ipr

        ipr.link('add', 
            ifname=self.veth_pair[0], 
            peer= self.veth_pair[1],
            kind='veth'
        )

        self.veth_pair = ipr.poll(
            ipr.link, 'dump', ifname=lambda x: x in self.veth_pair
        )

        for pair_index, link in enumerate(self.veth_pair):
            ipr.link('set', index=link['index'], state='up')
            ipr.addr('add', index=link['index'], address=f"192.168.32.{pair_index+1}", prefixlen=24)
    
    def remove_veth(self):
        ipr = IPRoute()
        veth_0 = ipr.poll(
            ipr.link, 'dump', ifname=netfilter_manager.veth_pair[1]
        )[0]
        ipr.link('del', index=veth_0['index'])



    def tear_down(self):
        self._ndb.close()
        self.ipr.close()
        self.remove_veth()
        netns.remove(self.netlink_ns)

    @staticmethod 
    def get_nft_rules(handles_bool, table='', chain=''):
        """Returns all lines defining the nft ruleset
            arguments:
             handles_bool - a boolean, whether or not to include handle references in the strings
        """
        nft = nftables.Nftables()
        nft.set_handle_output(handles_bool)

        if not table: #Then all rules
            return [
                line for line in nft.cmd("list ruleset")[1].split("\n")[:-1]
                    if not line == ''
            ]
        elif table and not chain: #Then whole table
            return [
                line for line in nft.cmd(f"list {table}")[1].split("\n")[:-1]
                    if not line == ''
            ]
        else: #Table and chain only
            return [
                line for line in nft.cmd(f"list {table} {chain}")[1].split("\n")[:-1]
                    if not line == ''
            ]

    @staticmethod
    def get_handles(table='', chain=''):
        """ returns a tuple with all rules+handles, 
        (optionally, for a specific table and chain)
        """

        handle_str_delim = "# handle "
        return [
            handle for _,handle in [
                rule.split(handle_str_delim) for rule in netfilter_manager.get_nft_rules(True)
                    if handle_str_delim in rule
            ]
        ]

    def insert_rule(self, rule, table='ip filter', chain='input', action='drop'):
        if not table in self._handle_lookup_map.keys():
            self._handle_lookup_map[table] = {}
        if not chain in self._handle_lookup_map[table].keys():
            self._handle_lookup_map[table][chain] = {}

        pre_insert_handles = self.get_handles(table=table, chain=chain)

        self._nft.cmd(f"add rule {table} {chain} {rule} {action}")
        kernel_handle_number = self._find_custom_rule_handle(pre_insert_handles, table=table, chain=chain)

        self._handle_lookup_map[table][chain][kernel_handle_number] = rule
        return kernel_handle_number

    def delete_rule(self, handle, table='ip filter', chain='input'):
        self.logger.debug(f"Deleting rule: delete rule {table} {chain} handle {handle}")
        self._nft.cmd(f"delete rule {table} {chain} handle {handle}")

    def flush_rules(self):
        for table in self._handle_lookup_map.keys():
            for chain in self._handle_lookup_map[table].keys():
                for rule_handle in self._handle_lookup_map[table][chain].keys():
                    self.delete_rule(
                        rule_handle,
                        table=table,
                        chain=chain
                    )


    def _find_custom_rule_handle(self, previous_handles, table='', chain=''):
        """Finds a new rule added to table+chain, for its kernel handle

        After adding a rule, one must list all rules to find its handle, 
        otherwise, atomicity is lost.

        This seems like a hotly debated topic: https://patchwork.ozlabs.org/project/netfilter-devel/patch/20170504123421.22147-1-phil@nwl.cc/ 
        and a failure of RedHat's, to have pushed out without a solution: https://access.redhat.com/solutions/5606371

        ... so add that to FoWL's features!

        """

        for handle in self.get_handles(table=table, chain=chain):
            if not handle in previous_handles:
                return handle

    # def redirect_rules_port(self, address, table='ip nat', chain='PREROUTING'):
    #     if not address in self.ignore_list:
    #         self.insert_rule(
    #             f"ip saddr {address}", 
    #             table=table, 
    #             chain=chain, 
    #             action="drop"
    #         )

    def in_FoWLands(self, address):
        return address in self.fowlin_host_list

    def redirect_to_FoWL_net(self, address, table='ip nat', chain='PREROUTING'):
        if not address in self.fowlin_host_list:
            self.insert_rule(
                f"ip saddr {address}", 
                table=table, 
                chain=chain, 
                action="dnat 192.168.32.2"
            )

            self.fowlin_host_list.append(address)
            self.logger.debug(f"Manipulating future host {address} traffic in FoWL Net")
        else:
            self.logger.debug(f"Host {address} is already in the FoWLands!")

    def ignore_host(self, address, table='ip filter', chain='INPUT'):
        if not address in self.ignore_list:
            self.insert_rule(
                f"ip saddr {address}", 
                table=table, 
                chain=chain, 
                action="drop"
            )
            self.ignore_list.append(address)
            self.logger.debug(f"Blocked {address} on via DROP action on table {table} chain {chain}")
        else:
            self.logger.debug(f"Host {address} is already ignored!")