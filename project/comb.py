from kivy.uix.floatlayout import FloatLayout
from kivy.uix.dropdown import DropDown
from kivy.uix.textinput import TextInput
from kivy.properties import ListProperty
from kivy.lang import Builder

Builder.load_string('''
#:import Button kivy.uix.button.Button
<MainView>:
    ComboEdit:
        size_hint: .5, .5
        pos_hint: {'center':(.5, .5)}
        options:
            [Button(text = str(x),\
                    size_hint_y=None,\
                    height=30)\
            for x in range(3)]
''')

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

class MainView(FloatLayout):
    pass

if __name__ == '__main__':
    from kivy.base import runTouchApp
    runTouchApp(MainView(width=800))
