from kivy.app import App
from kivy.lang import Builder
from kivy.uix.screenmanager import ScreenManager, Screen

# Create both screens. Please note the root.manager.current: this is how
# you can control the ScreenManager from kv. Each screen has by default a
# property manager that gives you the instance of the ScreenManager used.


# Declare both screens
class MenuScreen(Screen):
    pass

class SettingsScreen(Screen):
    pass
class UfalaScreen(Screen):
    pass

# Create the screen manager


class TestApp(App):

        
    def build(self):
        self.sm = ScreenManager()
        self.sm.add_widget(MenuScreen(name='menu'))
        self.sm.add_widget(SettingsScreen(name='settings'))
        self.sm.add_widget(UfalaScreen(name='ufala'))
        return self.sm

if __name__ == '__main__':
    TestApp().run()
