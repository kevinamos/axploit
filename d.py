from kivy.uix.dropdown import DropDown
from kivy.uix.button import Button
from kivy.base import runTouchApp

dropdown=DropDown()
for index in range(10):
	btn=Button(text='value %d ' % index, size_hint_y=None, height=20)
	btn.bind(on_release=lambda btn:dropdown.select(btn.text))
	dropdown.add_widget(btn)
mainbutton=Button(text='Select scan type', size_hint=(None, None))
mainbutton.bind(on_release=dropdown.open)
dropdown.bind(on_select=lambda instance, x:setattr(mainbutton, 'text', x) )

runTouchApp(mainbutton)


