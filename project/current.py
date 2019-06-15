#:kivy 1.0
#:import Button kivy.uix.button.Button
#:import KivyLexer kivy.extras.highlight.KivyLexer
<SettingsScreen>:
	Button:
		text:"app settings"

<MainWindow>:
	id:main

	fullscreen:True
	__safe_id:[dropdown.__self__]
    orientation: "vertical"
	foreground_color: (1, 1, 1, 1)
	
	canvas:
        Color:
            rgb: 1, 1, 1
        Rectangle:
            source: 'data/images/background.jpg'
            size: self.size

    pos_hint:{'top':1}
	#scan_results:scan_results 
    BoxLayout:    
        size_hint: (1,.05)

      
        orientation: "horizontal"
   
  
        Button:
            id: btn_save
            text: "Sniffer"
            border:3,3, 3,3
            on_press: root.get_sniffer_screen()
        Button:
            id: btn_Mitm
            text: "MItM  Attacks"
            on_press: root.Mitm()
            
        Button:
            id: btn_dos
            text: "DOS"
            on_press: root.DOS()

        Button:
            id: btn_copy
            text: "Wireless"
            on_press: root.on_copy()
            
            
        Button:
            id: btn_delete
            text: "Help"
            on_press: root.Help()
        Button:
        	text:"Settings"
        	on_press: root.manager.current = 'settings'
	BoxLayout:	
		id:scanner_body
		padding:20	
		orientation:'vertical'
		pos_hint:{'top':1}		   
		BoxLayout:
			orientation: "horizontal"		
			size_hint:(1,None)
			pos_hint:{'top':1}
			height:30
			TextInput:	
				pos_hint:{'top':1}			
				hint_text:"Target Host"	
				size_hint_x:None
				id:target_host
				width:600		
			Button:		
				pos_hint:{'top':1}
				text:'Choose a scan type'
				id:scan_type_choice
				on_release:dropdown.open(self)
				size_hint_x:None
				width:500
				
			Widget:
				on_parent:dropdown.dismiss()
			DropDown:
				id:dropdown
				on_select:scan_type_choice.text='{}'.format(args[1])
				Button:
					text:"Syn Scan"
					size_hint_y:None
					height:30
					on_release:dropdown.select('-sS')

				Button:
					text:"TCP connect scan"
					size_hint_y:None
					height:30
					on_release:dropdown.select('-sT')
				Button:
					text:"UDP scan -sU"
					size_hint_y:None
					height:30
					on_release:dropdown.select('-sU')
				Button:
					text:"Ack Scan"
					size_hint_y:None
					height:30
					on_release:dropdown.select('-sA')

				Button:
					text:"TCP Fin scan"
					size_hint_y:None
					height:30
					on_release:dropdown.select('-sF')
				Button:
					text:"Idle Scan"
					size_hint_y:None
					height:30
					on_release:dropdown.select('-sI')	
				Button:
					text:"Version Detection"
					size_hint_y:None
					height:30
					on_release:dropdown.select('-sV')		      				
			Button:
				text:'Scan'
				size_hint:(None,None)
				width:100
				pos_hint:{'top':1}
				height:30	
				on_press:root.start_scanner(scan_type_choice.text, target_host.text)
			Button:
				text:'Reset'
				size_hint:(None,None)
				width:100
				pos_hint:{'top':1}
				height:30	
				on_press:sr.clear_widgets()
				on_press:sr2.clear_widgets()
				on_press:target_host.text=''	
				on_press:scan_type_choice.text='Choose a scan type '
				background_color: (.140,.140,.140,1) if self.state == 'normal' else (0,1,0,1)
				background_normal: "" 
    
        
        
		BoxLayout:
			id: reactive_layout
			orientation: 'vertical' if self.width < self.height else 'horizontal'
			Splitter:
            	id: editor_pane
            	max_size: 400
            	min_size: 100
            	vertical: 1 if reactive_layout.width < reactive_layout.height else 0
            	sizable_from: 'bottom' if self.vertical else 'right'
            	size_hint: (1, None) if self.vertical else (None, 1)
            	size: 200, 400
            	on_vertical:
                	mid_size = self.max_size/2
                	if args[1]: self.height = mid_size
                	if not args[1]: self.width = mid_size
                BoxLayout:
	                Button:
	                	text:'Hosts'
	                	size_hint_y:None
	                	height:30
	                	
	                	pos_hint:{'top':1}
	                Button:
	                	text:'services'
	                	size_hint_y:None
	                	height:30
	                	pos_hint:{'top':1}
	                	
				ScrollView:
					scroll_type: ['bars', 'content']
					bar_width: 4
					size_hint_y:None
					height:600
					BoxLayout:
						orientation:'vertical'
						size_hint_y:None
						size_hint_x:.5
						spacing:0
						
			BoxLayout:
				orientation:'vertical'
				GridLayout:
					cols:3
					size_hint_x:1
					id:sr 	

				ScrollView:
					bar_width:10
					bar_color:(1,1,1,.6)
					size_hint_x:1
					scroll_type: ['bars', 'content']
					bar_width: 4
					size_hint_y:None
					height:600  
					BoxLayout:
						orientation:'vertical'
						size_hint_y:None
						size_hint_x:1
						spacing:0
						id:sr2              	
		# GridLayout:
		# 	cols:3
		# 	size_hint_x:.5
		# 	id:sr


		# ScrollView:
		# 	scroll_type: ['bars', 'content']
		# 	bar_width: 4
		# 	size_hint_y:None
		# 	height:600
		# 	BoxLayout:
				# canvas:
				# 	Color:
    #         			rgba: 47 / 255., 167 / 255., 212 / 255., .1
				# 	Rectangle:
    #         			pos: self.x, self.y + 1
				# 		size: self.size
				# 		Color:
				# 			rgb: .2, .2, .2
				# 	Rectangle:
				# 		pos: self.x, self.y - 2
				# 		size: self.width, 1
				# orientation:'vertical'
				# size_hint_y:None
				# size_hint_x:.5
				# spacing:0
				# id:sr2    
    
<Sniffer_screen>:
	pos_hint:{'top':1}
	canvas:
        Color:
            rgb: 1, 1, 1
        Rectangle:
            source: 'data/images/background.jpg'
            size: self.size
	BoxLayout:
		pos_hint:{'top':1}
		size_hint_x:.8
		padding:50

		Button:		
			pos_hint:{'top':1}
			size_hint:(1,.05)
			text:'Choose Interface'
			id:interface
			on_release:dropdown.open(self)
				
		Widget:
			on_parent:dropdown.dismiss()
		DropDown:
			id:dropdown
			on_select:interface.text='{}'.format(args[1])
			Button:
				text:"Eth0"
				size_hint_y:None
				height:30
				on_release:dropdown.select('Eth0')

			Button:
				text:"Wlan0"
				size_hint_y:None
				height:30
				on_release:dropdown.select('Wlan0')
		Button:		
			pos_hint:{'top':.9}
			size_hint:(1,.05)
			text:'Choose what to sniff'
			id:sniff_type
			on_release:dropdown.open(self)
				
		Widget:
			on_parent:dropdown.dismiss()
		DropDown:
			id:dropdown
			on_select:interface.text='{}'.format(args[1])
			Button:
				text:"Eth0"
				size_hint_y:None
				height:30
				on_release:dropdown.select('All')

			Button:
				text:"Passwords and usernames"
				size_hint_y:None
				height:30
				on_release:dropdown.select('passwords and usernames')
		Button:
			text:'Start'
			size_hint:(.4,None)
			pos_hint:{'top':.9}
			height:30	
			background_color: (0,1,0,1)
			background_normal: "" 
		Button:
			text:'Stop'
			spacing:10

			size_hint:(.4,None)
			pos_hint:{'top':.9}
			height:30	
			# ScrollView:
		# 	scroll_type: ['bars', 'content']
		# 	bar_width: 4
		# 	size_hint_y:None
		# 	height:600
		# 	BoxLayout:
		# 		orientation:'horizontal'
		# 		BoxLayout:
		# 			orientation:'vertical'
		# 			size_hint_y:None
		# 			size_hint_x:.5
		# 			spacing:0
				  
		# 		BoxLayout:
		# 			canvas:
		# 				Color:
	 #            			rgba: 47 / 255., 167 / 255., 212 / 255., .1
		# 				Rectangle:
	 #            			pos: self.x, self.y + 1
		# 					size: self.size
		# 					Color:
		# 						rgb: .2, .2, .2
		# 				Rectangle:
		# 					pos: self.x, self.y - 2
		# 					size: self.width, 1
		# 			orientation:'vertical'
		# 			size_hint_y:None
		# 			size_hint_x:.5
		# 			spacing:0
		# 			id:sr2    
				   
		
		# 