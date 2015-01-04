# SMOC - Simple Multipath OpenFlow Controller
# Version 0
#
# Modified for SMOC Project
# Changes:
#  Added transport-layer information tabl
#  Added different-path switching strategy support
#
# SMOC is not owned, managed, or endorsed by NTT.
# Copyright text below kept for compliance only.
#

# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import struct

from ryu.base import app_manager
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib import dpid as dpid_lib
from ryu.lib import stplib
print stplib.__file__
from ryu.lib.mac import haddr_to_str, haddr_to_bin

# debug
from pprint import pprint

# for topology stuff
from ryu.topology.api import *
from ryu.lib.packet import packet
from ryu.lib.ip import *
from mproute import MPRoute

# priority mods for SMOC/MPRoute functionality
HI_PRIORITY = 10
LO_PRIORITY = -10
MD_PRIORITY = 5

LLDP_ADDR = ['01:80:c2:00:00:0e','01:80:c2:00:00:03','01:80:c2:00:00:00']

class SimpleSwitchStp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]
    _CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchStp, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        # Maps subflow identifier src_ip, dst_ip to machine
        # TODO: Implement other ways to identify hosts and
        #       preferably trace/crack for flow identification
        self.logger.info("Creating static IP-host identification")
        self.subflow_map = {ipv4_to_bin('10.0.12.1'): 'sd-ofex-1',
                            ipv4_to_bin('10.0.13.1'): 'sd-ofex-1',
                            ipv4_to_bin('10.0.12.2'): 'sd-ofex-2',
                            ipv4_to_bin('10.0.23.2'): 'sd-ofex-2',
                            ipv4_to_bin('10.0.13.3'): 'sd-ofex-3',
                            ipv4_to_bin('10.0.23.3'): 'sd-ofex-3'}
        self.logger.info(self.subflow_map)

        # Topology information that's returned from MPRoute functions
        #  (calculated only at each topo change)
        self.linktopo = None

        self.stp = kwargs['stplib']

        # Sample of stplib config.
        #  please refer to stplib.Stp.set_config() for details.
        """
        config = {dpid_lib.str_to_dpid('0000000000000001'):
                     {'bridge': {'priority': 0x8000,
                                 'max_age': 10},
                      'ports': {1: {'priority': 0x80},
                                2: {'priority': 0x90}}},
                  dpid_lib.str_to_dpid('0000000000000002'):
                     {'bridge': {'priority': 0x9000}}}
        self.stp.set_config(config)
        """

    def safe_reject(self, datapath):
        # TODO: Permit all LLDPs, high priority
        ofproto = datapath.ofproto
        wildcards = ofproto_v1_0.OFPFW_ALL
        wildcards &= ~ofproto_v1_0.OFPFW_DL_DST
        matches = [datapath.ofproto_parser.OFPMATCH(
            wildcards, 0, 0, haddr_to_bin(lldp_addr),
            0, 0, 0, 0, 0, 0, 0, 0, 0) for lldp_addr in LLDP_ADDR]
        mods = [datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto_OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY+HI_PRIORITY)
            for match in matches]
        for mod in mods:
            datapath.send_msg(mod)

        # TODO: Reject all broadcast/multicast, low priority
        wildcards = ofproto_v1_0.OFPFW_ALL

    def block_port(self, datapath, in_port):
        # TODO: Drop all traffic from one port, moderate priority
        ofproto = datapath.ofproto
        wildcards = ofproto_v1_0.OFPFW_ALL
        wildcards &= ~ofproto_v1_0.OFPFW_IN_PORT
        match = datapath.ofproto_parser.OFPMatch(
            wildcards, in_port, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0)
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=None)
        datapath.send_msg(mod)

    def unblock_port(self, datapath, in_port):
        # Remove any blocks enforced by block_port
        ofproto = datapath.ofproto
        wildcards = ofproto_v1_0.OFPFW_ALL
        wildcards &= ~ofproto_v1_0.OFPFW_IN_PORT
        match = datapath.ofproto_parser.OFPMatch(
            wildcards, in_port, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0)
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_DELETE, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=None)
        datapath.send_msg(mod)

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        # TODO: Add TCP port matching

        wildcards = ofproto_v1_0.OFPFW_ALL
        wildcards &= ~ofproto_v1_0.OFPFW_IN_PORT
        wildcards &= ~ofproto_v1_0.OFPFW_DL_DST

        match = datapath.ofproto_parser.OFPMatch(
            wildcards, in_port, 0, dst,
            0, 0, 0, 0, 0, 0, 0, 0, 0)

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

        # DEBUG: show what is added
        self.logger.info(str(mod))


    def delete_flow(self, datapath):
        ofproto = datapath.ofproto

        wildcards = ofproto_v1_0.OFPFW_ALL
        match = datapath.ofproto_parser.OFPMatch(
            wildcards, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_DELETE)
        datapath.send_msg(mod)

    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        dst, src, _eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.debug("packet in %s %s %s %s",
                          dpid, haddr_to_str(src), haddr_to_str(dst),
                          msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        # TODO: mproute stuff
        self.topo = {}


        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, actions)

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        datapath.send_msg(out)

    @set_ev_cls(stplib.EventTopologyChange, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        dp = ev.dp
        dpid_str = dpid_lib.dpid_to_str(dp.id)
        msg = 'Receive topology change event. Flush MAC table.'
        self.logger.debug("[dpid=%s] %s", dpid_str, msg)

        if dp.id in self.mac_to_port:
            del self.mac_to_port[dp.id]

        #TODO: read topology
        S = [s.dp.id for s in get_all_switch(self)]
        L = [(link.src.dpid, link.dst.dpid) for link in get_all_link(self)]
        self.logger.info("Creating mproute instance")
        mproute = MPRoute(S,L)

        self.delete_flow(dp)

        print '1', dir(ev.dp)

        #Block all ports
        print dp.ports
        for port in dp.ports:
            self.block_port(dp, port)

        #Print rules

        for port in dp.ports:
            self.unblock_port(dp, port)

        self.logger.info("Sending safety rules to %s", dpid_str)

        M = [(s.dp, s.dp.id, s.ports) for s in S]
        self.logger.info(pprint(S))
        self.logger.info(pprint(L))
        self.logger.info(pprint(M))
        lel

    @set_ev_cls(stplib.EventPortStateChange, MAIN_DISPATCHER)
    def _port_state_change_handler(self, ev):
        dpid_str = dpid_lib.dpid_to_str(ev.dp.id)
        print '2', dir(ev)
        of_state = {stplib.PORT_STATE_DISABLE: 'DISABLE',
                    stplib.PORT_STATE_BLOCK: 'BLOCK',
                    stplib.PORT_STATE_LISTEN: 'LISTEN',
                    stplib.PORT_STATE_LEARN: 'LEARN',
                    stplib.PORT_STATE_FORWARD: 'FORWARD'}
        self.logger.debug("[dpid=%s][port=%d] state=%s",
                          dpid_str, ev.port_no, of_state[ev.port_state])
