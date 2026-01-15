import scapy.all as scapy

class DNSLearner:
    def __init__(self, iface, arp):
        self.iface = iface
        self.arp = arp

    def _handle_packet(self, pkt):
        if pkt.haslayer(scapy.DNS) and pkt.haslayer(scapy.IP):
            if pkt[scapy.DNS].qr == 0:
                dns_ip = pkt[scapy.IP].dst
                self.arp.set_dns(dns_ip)

    def start(self, stop_event):
        print("[DNSLearn]: Learning DNS Server...")
        while not stop_event.is_set():
            scapy.sniff(
                iface=self.iface,
                filter="udp port 53 or tcp port 53",
                prn=self._handle_packet,
                store=False,
                timeout=0.1
            )
