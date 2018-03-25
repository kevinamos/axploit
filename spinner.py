from kivy.app import App
from kivy.lang import Builder
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.boxlayout import BoxLayout
from kivy.animation import Animation
from kivy.properties import NumericProperty

Builder.load_string('''
<mainwindow>:
	BoxLayout:
		Button:
			size_hint:(.2, .1)
			text:'start'
			on_press:root.sn()

		Button:
			size_hint:(.2, .1)
			text:'stop'
			on_press:root.destroy()
	FloatLayout:
		hidden:True
		id:spin

		canvas.before:
			PushMatrix
			Rotate
				angle: root.angle
				axis:0, 0, 1
				origin:root.center
		canvas.after:
			PopMatrix
		Image:
			id:img_spin
			source:'btn1png'
			size_hint:None,None
			size:100, 100
			pos_hint:{'center_x':0.5, 'center_y': 0.5}

'''

)

class mainwindow(FloatLayout):
	angle=NumericProperty(0)
	def __init__(self, **kwargs):
		super(mainwindow, self).__init__(**kwargs)
		#self.sn()
	def sn(self, **kwargs):
		self.anim=Animation(angle=360, duration=5)
		self.anim+=Animation(angle=360, duration=5)
		self.anim.repeat=True
		self.anim.start(self)
	def create(self):
		pass
	def destroy(self):
		self.ids.spin.clear_widgets()
		
	def on_angle(self, item, angle):
		if angle==360:
			# self.anim.stop(self)
			item.angle=0

class TestApp(App):
	def build(self):
		return mainwindow()
TestApp().run()





