from kivy.app import App
from kivy.uix.label import Label
from kivy.core.text import LabelBase
from kivy.utils import get_color_from_hex
from kivy.core.window import Window
Window.clearcolor = get_color_from_hex('#101216')


class hellowApp(App):
	def build(self):
		return Label()
if __name__=='__main__':
	hellowApp().run()
	
	

