import scapy.all as scapy
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether
import logging
import threading
import time
import os

class Silent:
    def __init__(self, interface):
        self.targets = {}
        self.mac = scapy.get_if_hwaddr(interface)
        self.ip = scapy.get_if_addr(interface)
        self.iface = interface

    def filter(self, mac, ip):
        if mac == "ff:ff:ff:ff:ff:ff":
            return False
        if mac == self.mac:
            return False
        if ip == self.ip:
            return False
        return True

    def discover(self, stop_silent):
        try:
            while not stop_silent.is_set():
                pkt = scapy.sniff(iface=self.iface, store=0, timeout=1)
                #print(pkt)
                if IP in pkt:
                    if filter(pkt[Ether].src, pkt[IP].src) and pkt[IP].src not in self.targets:
                        self.targets.append(pkt[IP].src)
                        print(f"Targets found: {self.targets}")
                    if filter(pkt[Ether].dst, pkt[IP].dst) and pkt[IP].dst not in self.targets:
                        self.targets.append(pkt[IP].dst)
                        print(f"Targets found: {self.targets}")
                if ARP in pkt:
                    if filter(pkt[Ether].src, pkt[ARP].src) and pkt[ARP].src not in self.targets:
                        self.targets.append(pkt[ARP].src)
                        print(f"Targets found: {self.targets}")
                    if filter(pkt[Ether].dst, pkt[ARP].dst) and pkt[ARP].dst not in self.targets:
                        self.targets.append(pkt[ARP].dst)
                        print(f"Targets found: {self.targets}")
        except KeyboardInterrupt:
            pass
        except scapy.Scapy_Exception:
            print(f"! Couldn't sniff on interface {self.iface}. Exiting...")
            exit(1)