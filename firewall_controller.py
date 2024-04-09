# Lab5 Skeleton

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Routing(object):
    
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

    def do_routing(self, packet, packet_in, port_on_switch, switch_id):
        if packet.find('arp') or packet.find('icmp'):
            # Rule 1: Accept ARP and ICMP packets
            self.accept(packet_in, "ARP or ICMP", of.OFPP_NORMAL)
            return

        ipv4_packet = packet.find('ipv4')
        if ipv4_packet is not None:
            src_ip = str(ipv4_packet.srcip)
            dst_ip = str(ipv4_packet.dstip)
            log.debug("IPv4 packet from {} to {}".format(src_ip, dst_ip))

            # Check if the packet is TCP
            if packet.find('tcp'):
                # Rule 2: Forward TCP traffic based on specific conditions
                if (src_ip.startswith('10.0.2.') and dst_ip == '10.0.128.233') or \
                (src_ip == '10.0.128.233' and dst_ip.startswith('10.0.2.')):
                    # Accept TCP traffic from the Student LAN to destinations other than discordServer
                    self.accept(packet_in, "TCP traffic from Student LAN to discordServer", of.OFPP_NORMAL)
                    return
                elif (src_ip.startswith('10.0.1.') and dst_ip == '10.0.128.233') or \
                (src_ip == '10.0.128.233' and dst_ip.startswith('10.0.1.')):
                    # Drop TCP traffic from the Faculty LAN to destinations other than discordServer
                    self.drop(packet_in, "TCP traffic from Faculty LAN to non-discordServer destinations")
                    return
                elif (src_ip == '10.0.198.2' and dst_ip == '10.0.203.2') or \
                (src_ip == '10.0.203.2' and dst_ip == '10.0.198.2'):
                    # Accept TCP traffic between guestPC and trustedPC
                    self.accept(packet_in, "TCP traffic between guestPC and trustedPC", of.OFPP_NORMAL)
                    return
                elif dst_ip == '10.0.100.2' and not src_ip.startswith('10.0.1.'):
                    # Drop TCP traffic not originating from the Faculty LAN to the exam server
                    self.drop(packet_in, "TCP traffic from non-Faculty LAN to exam server")
                    return
                elif src_ip.startswith('10.0.100.') or \
                    src_ip.startswith('10.0.3.') or \
                    src_ip.startswith('10.0.1.') or \
                    src_ip.startswith('10.0.2.') or \
                    src_ip == '10.0.203.2':
                    # Forward TCP traffic from specified subnets or trustedPC
                    self.accept(packet_in, "Forward TCP traffic from specified subnets or trustedPC", of.OFPP_NORMAL)
                    return
                else:
                    # Drop TCP traffic not matching any rule
                    self.drop(packet_in, "Blocking TCP traffic not matching any rule")
                    return
            
            # Check if the packet is UDP
            if packet.find('udp'):
                # Rule 3: Forward UDP traffic based on specific conditions
                if (src_ip.startswith('10.0.2.') and dst_ip == '10.0.128.233') or \
                (src_ip == '10.0.128.233' and dst_ip.startswith('10.0.2.')):
                    # Accept TCP traffic from the Faculty LAN to destinations other than discordServer
                    self.accept(packet_in, "UDP traffic from Student LAN to discordServer", of.OFPP_NORMAL)
                    return
                elif (src_ip.startswith('10.0.1.') and dst_ip == '10.0.128.233') or \
                (src_ip == '10.0.128.233' and dst_ip.startswith('10.0.1.')):
                    # Drop TCP traffic from the Faculty LAN to destinations other than discordServer
                    self.drop(packet_in, "UDP traffic from Faculty LAN to non-discordServer destinations")
                    return
                elif (src_ip == '10.0.198.2' and dst_ip == '10.0.203.2') or \
                (src_ip == '10.0.203.2' and dst_ip == '10.0.198.2'):
                    # Drop UDP traffic from trustedPC and guestPC to other subnets
                    self.accept(packet_in, "Forward UDP traffic in Internet subnet", of.OFPP_NORMAL)
                    return
                elif (src_ip == '10.0.198.2' and dst_ip != '10.0.203.2') or \
                (src_ip == '10.0.203.2' and dst_ip != '10.0.198.2'):
                    # Drop UDP traffic from trustedPC and guestPC to other subnets
                    self.drop(packet_in, "Drop UDP traffic from trustedPC and guestPC to other subnets")
                    return
                elif src_ip.startswith('10.0.100.') or \
                    src_ip.startswith('10.0.3.') or \
                    src_ip.startswith('10.0.1.') or \
                    src_ip.startswith('10.0.2.') or \
                    src_ip == '10.0.203.2':
                    # Forward UDP traffic from specified subnets
                    self.accept(packet_in, "Forward UDP traffic from specified subnets", of.OFPP_NORMAL)
                    return
                else:
                    # Drop UDP traffic not matching any rule
                    self.drop(packet_in, "Blocking UDP traffic not matching any rule")
                    return

        # Rule 4: Packet does not match any rule, drop it
        self.drop(packet_in, "Not matching any rule")

    
    def accept(self, packet_in, reason, end_port):
        msg = of.ofp_flow_mod()
        msg.data = packet_in
        msg.match = of.ofp_match.from_packet(packet_in)
        msg.actions.append(of.ofp_action_output(port=end_port))
        msg.buffer_id = packet_in.buffer_id
        self.connection.send(msg)
        log.info("Packet accepted: {}".format(reason))

    def drop(self, packet_in, reason):
        msg = of.ofp_packet_out()
        msg.data = packet_in
        msg.buffer_id = packet_in.buffer_id
        self.connection.send(msg)
        log.info("Packet dropped: {}".format(reason))

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp
        port_on_switch = packet_in.in_port
        switch_id = event.connection.dpid
        self.do_routing(packet, packet_in, port_on_switch, switch_id)

def launch():
    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Routing(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)