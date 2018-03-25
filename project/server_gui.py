#!/usr/bin/env python
from tkinter import *

update=0
def new_file():
    print ("Open new file")

def open_file():
	ftypes = [('Python files', '*.py'), ('All files', '*')]
	fl = askopenfile(parent=root,mode='rb',title='Select a file', filetypes = ftypes)
		
	if fl != None:
		contents = fl.read()
		n=Text(separator)
		n.insert(INSERT, contents)
		n.pack()
		
		fl.close()

def stub_action():
    print ("Menu select")
def Scanner():
	Label(separator, text="Target horst:").pack(side=LEFT, padx=5, pady=5)
	e = StringVar()
	e.set('choose scan type')
	en=Text(separator, width=40)
	en.configure(height=2)
	en.pack(side=LEFT)
	option=OptionMenu(separator,e, 'Syn', 'Xmas', 'Null').pack(side=LEFT)
	
	b=Button(separator,text='Scan')
	
	
	b.configure(background='black', fg='white', width=8, height=1, font = 'Helvetica 12 bold italic', cursor='hand2')
	
	b.pack(side=LEFT)

def FileMenu():
    CmdBtn = Menubutton(mBar, text='File', underline=0)
    CmdBtn.pack(side=LEFT, padx="2m")
    CmdBtn.menu = Menu(CmdBtn)
    CmdBtn.menu.add_command(label="Undo")
    CmdBtn.menu.entryconfig(0, state=DISABLED)
    CmdBtn.menu.add_command(label='New...', underline=0, command=new_file)
    CmdBtn.menu.add_command(label='Open...', underline=0, command=open_file)
    CmdBtn.menu.add_command(label='Wild Font', underline=0,
		font=('Tempus Sans ITC', 14), command=stub_action)
    CmdBtn.menu.add_command(bitmap="@bitmaps/RotateLeft")
    CmdBtn.menu.add('separator')
    CmdBtn.menu.add_command(label='Quit', underline=0, 
		background='white', activebackground='green', 
		command=CmdBtn.quit)
    CmdBtn['menu'] = CmdBtn.menu
    return CmdBtn

def ScannerMenu():
	ScannerBtn = Menubutton(mBar, text='Scanner', underline=0)
	ScannerBtn.pack(side=LEFT, padx="2m")
	ScannerBtn.menu = Menu(ScannerBtn)
	ScannerBtn.menu.choices = Menu(ScannerBtn.menu) 
	#start   
	ScannerBtn['menu'] = ScannerBtn.menu
	ScannerBtn.menu.add_radiobutton(label='start Scanner', command=Scanner)
	ScannerBtn.menu.add_radiobutton(label='View Scans')
	#end
	return ScannerBtn

def ExploitsMenu():
    ChkBtn = Menubutton(mBar, text='Exploits', underline=0)
    ChkBtn.pack(side=LEFT, padx='2m')
    ChkBtn.menu = Menu(ChkBtn)

    ChkBtn.menu.add_checkbutton(label='TCP Attacks')
    ChkBtn.menu.add_checkbutton(label='Layer 2 Attacks')
    ChkBtn.menu.add_checkbutton(label="DNS/UDP")
    ChkBtn.menu.add_checkbutton(label="Http Attacks")

    ChkBtn['menu'] = ChkBtn.menu
    return ChkBtn
def SnifferMenu():
    ChkBtn = Menubutton(mBar, text='Sniffer', underline=0)
    ChkBtn.pack(side=LEFT, padx='2m')
    ChkBtn.menu = Menu(ChkBtn)

    ChkBtn.menu.add_checkbutton(label='password sniffer')
    ChkBtn.menu.add_checkbutton(label='LAN packet sniffer')
  

    ChkBtn['menu'] = ChkBtn.menu
    return ChkBtn

def makeRadiobuttonMenu():
    RadBtn = Menubutton(mBar, text='Post EXploitation', underline=0)
    RadBtn.pack(side=LEFT, padx='2m')
    RadBtn.menu = Menu(RadBtn)

    RadBtn.menu.add_radiobutton(label='')
    RadBtn.menu.add_radiobutton(label='')
    RadBtn['menu'] = RadBtn.menu
    return RadBtn
def ExploitDetectorMenu():
    RadBtn = Menubutton(mBar, text='Detector', underline=0)
    RadBtn.pack(side=LEFT, padx='2m')
    RadBtn.menu = Menu(RadBtn)

    RadBtn.menu.add_radiobutton(label='Port scan detector')
    RadBtn.menu.add_radiobutton(label='sniffer detector')
    RadBtn.menu.add_radiobutton(label='ARP Watcher')
    RadBtn['menu'] = RadBtn.menu
    return RadBtn

def ForensicsMenu():
    RadBtn = Menubutton(mBar, text='Forensics', underline=0)
    RadBtn.pack(side=LEFT, padx='2m')
    RadBtn.menu = Menu(RadBtn)

    RadBtn.menu.add_radiobutton(label='Logs')
   

    RadBtn['menu'] = RadBtn.menu
    return RadBtn


def makeDisabledMenu(): 
    Dummy_button = Menubutton(mBar, text='Disabled Menu', underline=0)
    Dummy_button.pack(side=LEFT, padx='2m')
    Dummy_button["state"] = DISABLED
    return Dummy_button

root = Tk()
mBar = Frame(root, relief=RAISED, borderwidth=2)
mBar.pack(fill=X)
w, h = (root.winfo_screenwidth()-2), (root.winfo_screenheight()-1)
root.resizable(0,0)
root.geometry(str(w ) + 'x'+ str(h))
root.title("K3Xploit")
separator = Frame(height=10)
separator.pack(fill=X, padx=5, pady=40)

#root.configure(bg='#227bad')

CmdBtn = FileMenu()
ScannerMenu = ScannerMenu()
Sniffer=SnifferMenu()
ExploitsMenu = ExploitsMenu()
RadBtn = makeRadiobuttonMenu()
Forensics=ForensicsMenu()
ExploitDetector=ExploitDetectorMenu()



#NoMenu = makeDisabledMenu()

mBar.tk_menuBar(CmdBtn, Sniffer, ScannerMenu, ExploitsMenu, RadBtn,  ExploitDetector, Forensics)


#e.set("'A shroe! A shroe! My dingkom for a shroe!'")
Message(separator, text="Exactly.  It's my belief that these sheep are laborin' "
      "under the misapprehension that they're birds.  Observe their "
      "be'avior. Take for a start the sheeps' tendency to 'op about "
      "the field on their 'ind legs.  Now witness their attmpts to "
      "fly from tree to tree.  Notice that they do not so much fly "
      "as...plummet.", bg='royalblue',
      fg='ivory', relief=GROOVE)#.pack(padx=10, pady=10)


root.mainloop()






