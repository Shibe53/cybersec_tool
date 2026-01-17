import scapy.all as scapy
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether
import logging
import threading
import time
import os

class Silent:
    def __init__(self, interface):
        self.target_ips = list()
        self.target_macs = dict()
        self.mac = scapy.get_if_hwaddr(interface)
        self.ip = scapy.get_if_addr(interface)
        self.iface = interface

    def add_target(self, mac, ip):
        if ip not in self.target_ips:
            self.target_ips.append(ip)
            self.target_macs[ip] = mac
            print(f"Targets found: {self.target_ips}")

    def filter(self, mac, ip):
        if mac == "ff:ff:ff:ff:ff:ff":
            return
        if mac == self.mac:
            return
        if ip == self.ip:
            return
        self.add_target(mac, ip)

    def analyze(self, pkt):
        if IP in pkt:
            self.filter(pkt[Ether].src, pkt[IP].src)
            self.filter(pkt[Ether].dst, pkt[IP].dst)
        if ARP in pkt:
            self.filter(pkt[Ether].src, pkt[ARP].src)
            self.filter(pkt[Ether].dst, pkt[ARP].dst)

    def discover(self, stop_silent):
        try:
            while not stop_silent.is_set():
                scapy.sniff(iface=self.iface, prn=self.analyze, store=0, promisc=True, timeout=1)
        except KeyboardInterrupt:
            pass
        except scapy.Scapy_Exception:
            print(f"! Couldn't sniff on interface {self.iface}. Exiting...")
            exit(1)