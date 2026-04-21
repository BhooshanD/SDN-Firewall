from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, udp


class FirewallController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FirewallController, self).__init__(*args, **kwargs)

        # MAC learning table: { dpid: { mac: port } }
        self.mac_table = {}

        # Blocked IP pairs (bidirectional)
        # Add or remove pairs here as needed
        self.blocked_pairs = {
            ('10.0.0.1', '10.0.0.2')
        }

    def is_blocked(self, src_ip, dst_ip):
        return (src_ip, dst_ip) in self.blocked_pairs or \
               (dst_ip, src_ip) in self.blocked_pairs

    # ── Install table-miss flow on switch connect ─────────────────────────────
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss: send all unmatched packets to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)
        self.logger.info("Switch %s connected", datapath.id)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def drop_flow(self, datapath, priority, match):
        parser = datapath.ofproto_parser
        # No actions = DROP
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                 match=match, instructions=[])
        datapath.send_msg(mod)

    def send_packet_out(self, datapath, buffer_id, in_port, actions, data=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # ── Main PacketIn handler ─────────────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            return

        src_mac = eth.src
        dst_mac = eth.dst

        # Init MAC table for this switch
        if dpid not in self.mac_table:
            self.mac_table[dpid] = {}

        # Learn source MAC
        self.mac_table[dpid][src_mac] = in_port

        # Lookup destination port
        out_port = self.mac_table[dpid].get(dst_mac, ofproto.OFPP_FLOOD)

        # ── Skip DNS ──────────────────────────────────────────────────────────
        udp_pkt = pkt.get_protocol(udp.udp)
        if udp_pkt and (udp_pkt.dst_port == 53 or udp_pkt.src_port == 53):
            return

        # ── ARP handling ──────────────────────────────────────────────────────
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            if self.is_blocked(src_ip, dst_ip):
                self.logger.info("BLOCKED ARP: %s -> %s", src_ip, dst_ip)
                return
            actions = [parser.OFPActionOutput(out_port)]
            self.send_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                 in_port, actions, msg.data)
            return

        # ── IPv4 handling ─────────────────────────────────────────────────────
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            # Non-IP, non-ARP: just forward
            actions = [parser.OFPActionOutput(out_port)]
            self.send_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                 in_port, actions, msg.data)
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        # ── BLOCK TRAFFIC (bidirectional) ─────────────────────────────────────
        if self.is_blocked(src_ip, dst_ip):
            self.logger.info("BLOCKED: %s -> %s", src_ip, dst_ip)
            match = parser.OFPMatch(eth_type=0x0800,
                                    ipv4_src=src_ip, ipv4_dst=dst_ip)
            self.drop_flow(datapath, priority=10, match=match)
            return

        # ── ALLOW TRAFFIC with MAC learning ───────────────────────────────────
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            self.logger.info("LEARNED: %s -> %s out port %s", src_ip, dst_ip, out_port)
            match = parser.OFPMatch(eth_type=0x0800,
                                    ipv4_src=src_ip, ipv4_dst=dst_ip)
            # Install flow and forward current packet
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, priority=5, match=match,
                              actions=actions, buffer_id=msg.buffer_id)
                return
            else:
                self.add_flow(datapath, priority=5, match=match, actions=actions)
        else:
            self.logger.info("FLOODING (unknown dst): %s -> %s", src_ip, dst_ip)

        # Re-inject the triggering packet so it isn't lost
        self.send_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                             in_port, actions, msg.data)
