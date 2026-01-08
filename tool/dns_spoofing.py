import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR

class DNSSpoof:
    def __init__(self, iface, victimIP, websiteIP):
        self.iface = iface
        self.victimIP = victimIP
        self.websiteIP = websiteIP

    # Sniff only DNS 
    def start(self, stop_event):
        while not stop_event.is_set():
            scapy.sniff(
                iface=self.iface,
                filter="udp port 53",
                prn=self.handle_dns,
                store=False,
                timeout=1
            )
    
    def handle_dns(self, pkt):
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            # TODO Do something meaningful here
            qname = pkt[DNSQR].qname.decode()
            src = pkt[scapy.IP].src
            print(f"[DNS] {src} asked for {qname}")