# Import some POX stuff
from pox.core import core                     # Main POX object
import pox.openflow.libopenflow_01 as of      # OpenFlow 1.0 library
# import pox.lib.packet as pkt                  # Packet parsing/construction
# from pox.lib.addresses import EthAddr         # Address types
# import pox.lib.revent as revent               # Event library
# import pox.lib.recoco as recoco               # Multitasking library
import networkx as nx
import utils
from binascii import hexlify, unhexlify
import struct
import random
import path_utils
import expiringdict
from hashlib import sha1
import itertools
from pprint import pprint
import traceback
import sys
import expiringdict as expdict
from pox.lib.packet.tcp import mptcp_opt as pox_mptcp
from pox.lib.packet.tcp import tcp as pox_tcp

TCP_OPTION_KIND_MPTCP = 0x1e

expdict_time = 600
expdict_len = 2000

#
# WARNING: ONE MACHINE MUST BE CONNECTED TO ONLY ONE SWITCH!!!!!!!
#          THAT SWITCH CAN HOWEVER CONNECT TO ANY NUMBER OF SWITCHES.
#          It's simpler to implement this way.
#          (We will upgrade it to include full-multihoming later.)
#

TCP_FIN = 0b1
TCP_SYN = 0b10
TCP_RST = 0b100
TCP_PSH = 0b1000
TCP_ACK = 0b10000
TCP_URG = 0b100000
TCP_ECN = 0b1000000
TCP_CWR = 0b10000000

MPTCP_SUBTYPES = {
            0: 'MP_CAPABLE',
            1: 'MP_JOIN',
            2: 'DSS',
            3: 'ADD_ADDR',
            4: 'REMOVE_ADDR',
            5: 'MP_PRIO',
            6: 'MP_FAIL',
            7: 'MP_FASTCLOSE'
        }

class PathSet(itertools.cycle):
    pass

class Overseer (object):
  """
  smoc = Modified for Simple Multipath Openflow Controller
  (Working Title)

  Logic changes:
    no bw/lat calculation
    use min-hop for MP_CAPABLE connection
    use any other path for MP_JOIN connection
        (with minimal overlapping segments)

  Overseer - POX Component Implementing Bandwith/Latency-aware OpenFlow Controller
  """

  # LATENCY_WEIGHT_LABEL = "latency"
  # BANDWIDTH_WEIGHT_LABEL = "inversed_bandwidth"

  _core_name = "overseer"  # We want to be core.overseer

  def __init__(self, flow_idle_timeout=10, flow_hard_timeout=400):
    core.listen_to_dependencies(self)

    self.log = core.getLogger()
    self.flow_idle_timeout = flow_idle_timeout
    self.flow_hard_timeout = flow_hard_timeout

    '''
    A pathset is just a bunch of paths put into itertools cycle type.
    Use next(pathset) to get next path.
    '''
    self.pending_capable = expdict.ExpiringDict(expdict_len, expdict_time) # (init_ip, init_port, listen_ip, listen_port) => (init_hash, pathset)
    self.pending_join = expdict.ExpiringDict(expdict_len, expdict_time) # (init_ip, init_port, listen_ip, listen_port) => (listen_hash, pathset)
    self.mptcp_connections = expdict.ExpiringDict(expdict_len, expdict_time) # (to_hash) => from_hash, pathset
    self.tcp_path_assignment = expdict.ExpiringDict(expdict_len, expdict_time) # (srcip, srcport, dstip, dstport) => path

    # TODO: support true-multihomed configs
    #       connections: (from_hash, from_sw, to_hash, to_sw) => pathset

  def _handle_overseer_topology_LinkUp(self, event):
    graph = core.overseer_topology.graph
    self.log.debug('linkup %s -- %s' % (event.dpid1, event.dpid2))

  def _handle_openflow_PacketIn(self, event):
    # TODO: Refactor this method
    packet = event.parsed
    source = packet.src
    destination = packet.dst
    path = None #no path yet, we will assign later

    if destination.is_multicast:
      # Flood the packet
      # TODO: Install new flow instead of crafting new packet (hold down?)
      message = of.ofp_packet_out()
      message.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
      message.buffer_id = event.ofp.buffer_id
      # message.data = event.ofp
      message.in_port = event.port
      event.connection.send(message)
      return

    entryByMAC = core.host_tracker.entryByMAC
    known_hosts = entryByMAC.keys()

    if (source not in known_hosts) or (destination not in known_hosts):
      # Ignore non-end-to-end packet
      return

    from_host = entryByMAC[source]
    to_host = entryByMAC[destination]

    ip_packet = None
    tcp_packet = None

    if packet.find("ipv4") is not None:
        ip_packet = packet.find("ipv4")

    if packet.find("tcp") is not None:
        tcp_packet = packet.find("tcp")
        mptcp_options = [option for option in tcp_packet.options if option.type == TCP_OPTION_KIND_MPTCP]

    # TODO: INSPECT MPTCP AND PERFORM INFORMATION BASE OPERATIONS HERE
    # (USE NEW FUNCTION IN utils)
    # TODO: Decouple from utils.inspect_mptcp_packet
    if tcp_packet is not None and len(mptcp_options)>0:
        mptcp_option = mptcp_options[0]
        self.log.info(str(mptcp_option))

        tcp_src = (ip_packet.srcip, tcp_packet.srcport)
        tcp_dst = (ip_packet.dstip, tcp_packet.dstport)
        if mptcp_option.subtype == pox_mptcp.MP_CAPABLE:
            if (tcp_packet.flags & (pox_tcp.SYN_flag | pox_tcp.ACK_flag)) and (tcp_dst, tcp_src) in self.pending_capable:
                #second CAPABLE packet (syn/ack) => establish connection
                init_hash, pathset = self.pending_capable[(tcp_dst, tcp_src)]
                listen_hash = sha1(mptcp_option.skey).hexdigest()[:8]
                back_pathset = self.get_multipath(from_host.dpid, to_host.dpid)
                # match from pending-database and add two connections
                self.mptcp_connections[init_hash] = (listen_hash, back_pathset)
                self.mptcp_connections[listen_hash] = (init_hash, pathset)

                # delete from pending-database
                self.pending_capable.pop((tcp_dst, tcp_src), None)
                self.log.info("MPTCP Established! %s [%s:%d] <=> %s [%s:%d]" % (init_hash, ip_packet.dstip, tcp_packet.dstport, listen_hash, ip_packet.srcip, tcp_packet.srcport))

                path = back_pathset.next()
                self.log.info("Path Chosen: %s from %s" % (path, back_pathset))

            elif tcp_packet.flags & pox_tcp.SYN_flag and not tcp_packet.flags & pox_tcp.ACK_flag:
                #first CAPABLE (syn) => new connection
                init_hash = sha1(mptcp_option.skey).hexdigest()[:8]
                pathset = self.get_multipath(from_host.dpid, to_host.dpid)
                self.pending_capable[(tcp_src, tcp_dst)] = (init_hash, pathset)
                #consider: get_multipath(from_host.dpid, to_host.dpid)
                self.log.info("MPTCP Pending Capable %s [%s:%d] ==> ??? [%s:%d]\n   Path: %s" % (init_hash, ip_packet.srcip, tcp_packet.srcport, ip_packet.dstip, tcp_packet.dstport, pathset))
                path = pathset.next()
                self.log.info("Path Chosen: %s from %s" % (path, pathset))
        elif mptcp_option.subtype == pox_mptcp.MP_JOIN:
            recvtok = None
            if mptcp_option.rtoken is not None:
                recvtok = hexlify(mptcp_option.rtoken)
            # get connection instance
            if recvtok in self.mptcp_connections and recvtok is not None:
                to_hash = recvtok
                from_hash, pathset = self.mptcp_connections[to_hash]
                self.log.info("JOIN: Matched CAPABLE Connection: %s [%s:%d] ==> %s [%s:%d]\n    Path: %s" % (from_hash, ip_packet.srcip, tcp_packet.srcport, to_hash, ip_packet.dstip, tcp_packet.dstport, pathset))
                # create entry in pending join
                self.pending_join[(tcp_src, tcp_dst)] = (from_hash, pathset)
                path = pathset.next()
                self.log.info("Path Chosen: %s from %s" % (path, pathset))
            elif (tcp_dst, tcp_src) in self.pending_join:
                # match from pending join
                init_hash, pathset = self.pending_join[(tcp_dst, tcp_src)]
                listen_hash, pathset = self.mptcp_connections[init_hash]
                some_hash, back_pathset = self.mptcp_connections[listen_hash]
                self.log.info("JOIN: Established JOIN Connection %s [%s:%d] <=> %s [%s:%d]\n    Path: %s" % (init_hash, ip_packet.dstip, tcp_packet.dstport, listen_hash, ip_packet.srcip, tcp_packet.srcport, back_pathset))
                # delete from pending join
                self.pending_join.pop((tcp_dst, tcp_src), None)
                path = pathset.next()
                self.log.info("Path Chosen: %s from %s" % (path, pathset))
            else:
                self.log.info("%s has no matched connection" % (recvtok))
        else: #other MPTCP: latch it along some path if it matches existing connection, else send it along shortest path
            pass

        self.log.info("/// Pending Capable Connections")
        self.log.info(self.pending_capable)
        self.log.info("/// Pending Join Connections")
        self.log.info(self.pending_join)
        self.log.info("/// Current Connections")
        self.log.info(self.mptcp_connections)
        self.log.info("///")
        if path is None:
            path = self.get_path(from_host.dpid, to_host.dpid, packet)
        self.tcp_path_assignment[(tcp_src, tcp_dst)] = path

    if path is None:
        path = self.get_path(from_host.dpid, to_host.dpid, packet)
    match = of.ofp_match.from_packet(packet)
    match.in_port = None

    self.log.info("Installing path from host %s to host %s" % (source, destination))

    # Install flows
    # TODO: Handle buffer_id properly
    # first = True
    for from_switch, to_switch in utils.pairwise(path):
      portByDpid = core.overseer_topology.graph.get_edge_data(from_switch, to_switch)["portByDpid"]
      #self.log.info("Installing flow from switch %x[%d] to switch %x" % (from_switch, portByDpid[from_switch], to_switch))
      message = of.ofp_flow_mod()
      message.match = match
      message.idle_timeout = self.flow_idle_timeout
      message.hard_timeout = self.flow_hard_timeout
      message.actions.append(of.ofp_action_output(port=portByDpid[from_switch]))

      # if first:
        # message.buffer_id = event.ofp.buffer_id
        # first = False

      core.overseer_topology.graph.node[from_switch]['connection'].send(message)

    # Install final flow
    #self.log.info("Installing final flow from switch %x[%d] to host %s" % (path[-1], to_host.port, destination))
    message = of.ofp_flow_mod()
    message.match = match
    message.idle_timeout = self.flow_idle_timeout
    message.hard_timeout = self.flow_hard_timeout
    message.actions.append(of.ofp_action_output(port=to_host.port))
    core.overseer_topology.graph.node[path[-1]]['connection'].send(message)

  def get_multipath(self, from_dpid, to_dpid):
    ''' Returns a cycle iterable aliased as PathSet '''
    primary_path = nx.shortest_path(core.overseer_topology.graph, from_dpid, to_dpid)
    path_list  = list(nx.all_simple_paths(core.overseer_topology.graph, from_dpid, to_dpid))
    path_list.remove(primary_path)
    path_list = path_utils.sort_path_list(primary_path, path_list)
    path_list.insert(0, primary_path)
    pathset = PathSet(path_list)
    self.log.info("Pathset Created: %s" % (path_list))
    return pathset

  def get_path(self, from_dpid, to_dpid, packet):
    # TODO: Support IPv6

    tcp_packet = packet.find("tcp")
    udp_packet = packet.find("udp")
    ip_packet = packet.find("ipv4")

    """
    PATH RULES
    For ordinary packets and MP_CAPABLE (primary) connections:
        - Use *the* shortest path
    For MP_JOIN (secondary subflows) connections:
        - Use least-conflicting, shortest path that's not used above
    """

    # get shortest paths
    shortest_path = nx.shortest_path(core.overseer_topology.graph, from_dpid, to_dpid)

    if tcp_packet is None:
        return shortest_path

    # get all paths
    alt_paths = list(nx.all_simple_paths(core.overseer_topology.graph, from_dpid, to_dpid))
    alt_paths.remove(shortest_path)

    #prevents path assignment error on single path (retain backwards-compat)
    if alt_paths == []:
        alt_paths.append(shortest_path)

    alt_paths = path_utils.sort_path_list(shortest_path, alt_paths)

    # if MP_JOIN packet detected
    if tcp_packet is not None:
        for option in tcp_packet.options:
            #self.log.debug('%s %s' % (option.type, type(option.val)))
            if option.type == TCP_OPTION_KIND_MPTCP:
                mptcp_subtype = option.subtype
                self.log.info('MPTCP opt: %s' % MPTCP_SUBTYPES[mptcp_subtype])
                if mptcp_subtype == 1:
                    #pick the first Alt. Path
                    self.log.info("MP_JOIN => Alt. Path")
                    self.log.info("PATH: %s" % (alt_paths[0]))
                    return alt_paths[0]
                elif mptcp_subtype == 0:
                    self.log.info("MPTCP %s => Primary Path" % (MPTCP_SUBTYPES[mptcp_subtype]))
                    self.log.info("PATH: %s" % (shortest_path))
                    return shortest_path
                else:
                    return shortest_path

    # if all else fails, use default Overseer behavior
    return nx.shortest_path(core.overseer_topology.graph, from_dpid, to_dpid)

  def _handle_openflow_ErrorIn(self, event):
    # Log all OpenFlow errors
    self.log.error("OF:%s" % event.asString())

  def _handle_overseer_topology_Update(self, event):
    # TODO: Update all-pair shortest paths using Floyd-Warshall algorithm
    pass
