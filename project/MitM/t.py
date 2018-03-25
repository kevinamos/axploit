import scapy.all as scapy



def handle_packet(packet):
	print packet.show()


scapy.sniff(iface='lo', filter='port 53', prn=handle_packet)
