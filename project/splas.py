from kivy.app import App
from kivy.uix.image import Image
from kivy.animation import Animation
from kivy.clock import Clock


class timer():
    def work1(self):
        print('Hello World')

class arge(App):
    def build(self):
        wing = Image(source='liquid.bmp',pos=(800,800))
        animation = Animation(x=0, y=0, d=10, t='out_bounce');
        animation.start(wing)
        Clock.schedule_once(timer.work1, 10)
        return wing

if __name__ == '__main__':
    arge().run()
