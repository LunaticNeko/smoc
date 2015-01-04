# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""

import logging
import struct

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import tcp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import icmp
from ryu.lib.dpid import dpid_to_str, str_to_dpid

from ryu.topology.api import *
from mproute import MPRoute
from pprint import pprint
from time import sleep

# priority mods for SMOC/MPRoute functionality
HI_PRIORITY = 10
LO_PRIORITY = -10
MD_PRIORITY = 5

LLDP_ADDR = ['01:80:c2:00:00:0e','01:80:c2:00:00:03','01:80:c2:00:00:00']

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        # format: hash dpid => port_no[]
        self.internal_ports = {}
        self.disabled_ports = {}

        self.spanning_tree = None

    def update_spanning_tree(self):
        switches = get_switch(self)
        links = get_link(self)
        ports = [(switch, switch.ports) for switch in switches]
        switches = [dpid_to_str(switch.dp.id) for switch in switches]
        links = [(dpid_to_str(link.src.dpid), dpid_to_str(link.dst.dpid)) for link in links]

        print 'Controller: Generating Spanning Tree\nV = %s\nE = %s' % (switches,links)
        self.spanning_tree = MPRoute(switches,links)

    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

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

    def block_port(self, datapath, port):
        # Drop all traffic from one port EXCEPT LLDP, moderate priority
        self.logger.info('MPR BLOCK %s %s' % (datapath, port))
        ofproto = datapath.ofproto
        wildcards = ofproto_v1_0.OFPFW_ALL
        wildcards &= ~ofproto_v1_0.OFPFW_IN_PORT
        match = datapath.ofproto_parser.OFPMatch(
            wildcards, port.port_no, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0)
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=None)
        datapath.send_msg(mod)

        # Apply NO_FLOOD (taken from STPLIB)
        parser = datapath.ofproto_parser
        mask = 0b1111111
        msg = parser.OFPPortMod(datapath, port.port_no, port.hw_addr, ofproto_v1_0.OFPPC_NO_FLOOD, mask, port.advertised)


    ''' applies openflow NO_FWD to port, or all ports'''
    def no_fwd(self, datapath, port='all', value=True):
        self.logger.info('MPR NO_FWD %s %s %s' % (datapath, port, value))
        ofproto = datapath.ofproto
        wildcards = ofproto_v1_0.OFPFW_ALL
        if port != 'all':
            wildcards &= ~ofproto_v1_0.OFPFW_IN_PORT
            match = datapath.ofproto_parser.OFPMatch(
                wildcards, port.port_no, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0)
        else:
            match = datapath.ofproto_parser.OFPMatch(
                wildcards, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0)

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=None)
        datapath.send_msg(mod)

    def unblock_port(self, datapath, port):
        # Undo block_port
        ofproto = datapath.ofproto
        wildcards = ofproto_v1_0.OFPFW_ALL
        wildcards &= ~ofproto_v1_0.OFPFW_IN_PORT
        match = datapath.ofproto_parser.OFPMatch(
            wildcards, port.port_no, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0)
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_DELETE, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=None)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        p_tcp = pkt.get_protocol(tcp.tcp)
        p_ipv4 = pkt.get_protocol(ipv4.ipv4)
        p_ipv6 = pkt.get_protocol(ipv6.ipv6)
        p_icmp = pkt.get_protocol(icmp.icmp)

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        self.update_spanning_tree()
        print self.spanning_tree

        if p_tcp is not None:
            print "TCP?"
            print p_tcp.option

        if p_icmp is not None and p_ipv4 is not None:
            print "ICMP:", p_ipv4.src, '=>', p_ipv4.dst

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    #@set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    #def _state_change_handler(self, ev):
        #dp = ev.datapath
        #ports = dp.ports
        #ofproto = dp.ofproto
        #print '----', dp.id, '----'
        #pprint(dp.ports)
        #print '----'
    #    self.update_spanning_tree()
    #    ''' no_fwd this dpid '''
    #    dpid = ev.datapath.id
    #    self.no_fwd(ev.datapath, port='all', value=True)


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no
        dp = msg.datapath

        print '----'
        print dp, port_no, dp.ports[port_no], ev.msg.desc.state
        print '----'
        print dir(ev.msg.desc)
        print '----'
        print dp.ports


        # rebuild spanning tree
        #self.update_spanning_tree()

        print 'test block'
        #self.block_port(dp, dp.ports[port_no])

        print 'test unblock'
        #self.unblock_port(dp, dp.ports[port_no])

        #switches = get_all_switch(self)
        #links = get_all_link(self)
        #print '%d SWITCHES %s' % (len(switches), [switch.dp.id for switch in switches])
        #print '%d LINKS %s' % (len(links), [(link.src.dpid, link.dst.dpid) for link in links])
        #print dir(list(links)[0].src)
        #print dir(switches[0].dp.id)

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illegal port state %s %s", port_no, reason)
