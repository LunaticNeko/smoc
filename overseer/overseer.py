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

TCP_OPTION_KIND_MPTCP = 0x1e

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
  SMOC = Modified for Simple Multipath Openflow Controller
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

  def __init__(self, flow_idle_timeout=10, flow_hard_timeout=30):
    core.listen_to_dependencies(self)

    self.log = core.getLogger()
    self.flow_idle_timeout = flow_idle_timeout
    self.flow_hard_timeout = flow_hard_timeout

    '''
    A pathset is just a bunch of paths put into itertools cycle type.
    Use next(pathset) to get next path.
    '''
    self.pending_capable = {} # (init_ip, init_port, listen_ip, listen_port) => (init_hash, pathset)
    self.pending_join = {} # (init_ip, init_port, listen_ip, listen_port) => (listen_hash, pathset)
    self.mptcp_connections = {} # (from_hash, to_hash) => pathset

  def _handle_overseer_topology_LinkUp(self, event):
    graph = core.overseer_topology.graph
    self.log.debug('linkup %s -- %s' % (event.dpid1, event.dpid2))

  def _handle_openflow_PacketIn(self, event):
    # TODO: Refactor this method
    packet = event.parsed
    source = packet.src
    destination = packet.dst

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

    # TODO: INSPECT MPTCP AND PERFORM INFORMATION BASE OPERATIONS HERE
    # (USE NEW FUNCTION IN utils)
    tcp_packet = packet.find("tcp")
    if tcp_packet is not None:
        mptcp_packet_info = utils.inspect_mptcp_packet(packet)
        tcp_src = (mptcp_packet_info.srcip, mptcp_packet_info.srcport)
        tcp_dst = (mptcp_packet_info.dstip, mptcp_packet_info.dstport)
        self.log.info("MPTCP Packet Info:" % (vars(mptcp_packet_info)))
        if isinstance(mptcp_packet_info, utils.MPTCPCapablePacketInfo):
            if mptcp_packet_info.length == 12:
                if (mptcp_packet_info.tcpflags & (TCP_SYN | TCP_ACK)) and (tcp_dst, tcp_src) in self.pending_capable:
                    #second CAPABLE packet (syn/ack) => establish connection
                    init_hash, pathset = self.pending_capable[(tcp_dst, tcp_src)]
                    listen_hash = sha1(mptcp_packet_info.sendkey).hexdigest()[:8]
                    self.log.info("MPTCP Established! %s [%s:%d] <=> %s [%s:%d]" % (init_hash, mptcp_packet_info.dstip, mptcp_packet_info.dstport, listen_hash, mptcp_packet_info.srcip, mptcp_packet_info.srcport))
                elif mptcp_packet_info.tcpflags & TCP_SYN and not mptcp_packet_info.tcpflags & TCP_ACK:
                    #first CAPABLE (syn) => new connection
                    init_hash = sha1(mptcp_packet_info.sendkey).hexdigest()[:8]
                    multipath_entry = self.get_multipath(from_host.dpid, to_host.dpid)
                    self.pending_capable[(tcp_src, tcp_dst)] = (init_hash, multipath_entry)
                    #consider: get_multipath(from_host.dpid, to_host.dpid)
                    self.log.info("MPTCP Pending Capable %s [%s:%d] ==> ??? [%s:%d]\n   Path: %s" % (init_hash, mptcp_packet_info.srcip, mptcp_packet_info.srcport, mptcp_packet_info.dstip, mptcp_packet_info.dstport, multipath_entry))
                self.log.info("Pending Capable Connections")
                self.log.info(self.pending_capable)
                self.log.info("///")
            elif mptcp_packet_info.length == 20:
                #get info from pending_capable
                pass
            else:
                raise utils.MPTCPInvalidLengthException('Length should be 12 or 20, got %d (actually shouldn\'t have passed the inspect function. how did this happen?)'% (mptcp_packet_info.length))




    path = self.get_path(from_host.dpid, to_host.dpid, packet)
    match = of.ofp_match.from_packet(packet)
    match.in_port = None

    self.log.info("Installing path from host %s to host %s" % (source, destination))

    # Install flows
    # TODO: Handle buffer_id properly
    # first = True
    for from_switch, to_switch in utils.pairwise(path):
      portByDpid = core.overseer_topology.graph.get_edge_data(from_switch, to_switch)["portByDpid"]
      self.log.info("Installing flow from switch %x[%d] to switch %x" % (from_switch, portByDpid[from_switch], to_switch))
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
    self.log.info("Installing final flow from switch %x[%d] to host %s" % (path[-1], to_host.port, destination))
    message = of.ofp_flow_mod()
    message.match = match
    message.idle_timeout = self.flow_idle_timeout
    message.hard_timeout = self.flow_hard_timeout
    message.actions.append(of.ofp_action_output(port=to_host.port))
    core.overseer_topology.graph.node[path[-1]]['connection'].send(message)

  def get_multipath(self, from_dpid, to_dpid):
    ''' Returns a cycle iterable aliased as PathSet '''
    return PathSet(list(nx.all_simple_paths(core.overseer_topology.graph, from_dpid, to_dpid)))

  def get_mptcp_path(self, src_token=None, dst_token=None):
    # search connection table
    # search pathset table
    pass

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

    self.log.info("Getting Path (getpath)")
    #debug
    #traceback.print_stack(file=sys.stdout)


    # get shortest paths
    shortest_path = nx.shortest_path(core.overseer_topology.graph, from_dpid, to_dpid)

    # if not TCP => completely ignore and use shortest path
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
        #scan type for 1e
        for option in tcp_packet.options:
            #self.log.debug('%s %s' % (option.type, type(option.val)))
            if option.type == TCP_OPTION_KIND_MPTCP:
                self.log.info("Got MPTCP packet")
                #Unpack one half-byte from the option (MPTCP Subtype)
                mptcp_subtype = struct.unpack('B', option.val[0])[0] >> 4
                self.log.info('TCPopt: %s' % (hexlify(option.val)))
                #self.log.debug(MPTCP_SUBTYPES[mptcp_subtype])
                if mptcp_subtype == 1:
                    #pick the first Alt. Path
                    self.log.info("MP_JOIN => Alt. Path")
                    self.log.info("PATH: %s" % (alt_paths[0]))
                    return alt_paths[0]
                elif mptcp_subtype == 0:
                    self.log.info("MPTCP %s => Primary Path" % (MPTCP_SUBTYPES[mptcp_subtype]))
                    self.log.info("PATH: %s" % (shortest_path))
                    return shortest_path

    # if all else fails, use default Overseer behavior
    return nx.shortest_path(core.overseer_topology.graph, from_dpid, to_dpid)

  def _handle_openflow_ErrorIn(self, event):
    # Log all OpenFlow errors
    self.log.error("OF:%s" % event.asString())

  def _handle_overseer_topology_Update(self, event):
    # TODO: Update all-pair shortest paths using Floyd-Warshall algorithm
    pass
