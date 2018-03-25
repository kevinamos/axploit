#!/usr/bin/env python
from Tkinter import *


class calcApp:

    def __init__(self, root):
        self.setvalues=StringVar()
        
        self.equa=''
        self.topframe=Frame(root)
        self.topframe.pack()
        self.keyboardframe=Frame(root)
        self.keyboardframe.pack()

        self.root=root

 
    def create_buttons(self):
        c=0
        r=0
        b_count=[]

        for i in range(0, 16):
            if (i>=9):
                
                if i==9:
                
                    b=Button(self.keyboardframe, text=str(0), command=lambda
                             arg1=b, arg2=0:
                             self.buttonPress(arg2))
            
                    b.configure(background='black', fg='white', width=8, height=3,font = 'Helvetica 12 bold italic', cursor='hand2')
                    
                if i==10:
                
                    b=Button(self.keyboardframe, text=str('+'), command=lambda
                             arg1=b, arg2='+':
                             self.buttonPress(arg2))
            
                    b.configure(background='black', fg='white',  width=8, height=3,font = 'Helvetica 12 bold italic', cursor='hand2')
                if i==11:
                    
                    b=Button(self.keyboardframe, text=str('-'),command=lambda
                             arg1=b, arg2='-':
                             self.buttonPress(arg2))
            
                    b.configure(background='black', fg='white',  width=8, height=3, font = 'Helvetica 12 bold italic',cursor='hand2')

                if i==12:
                    
                    
                    b=Button(self.keyboardframe, text=str('C'), command=self.clearStuff)
            
                    b.configure(background='black', fg='white',  width=8, height=3, font = 'Helvetica 12 bold italic',cursor='hand2')

                if i==13:
                    
                    b=Button(self.keyboardframe, text=str('Ans'), command=self.answer)
            
                    b.configure(background='black', fg='white',  width=8, height=3, font = 'Helvetica 12 bold italic',cursor='hand2')
                if i==14:
                    b=Button(self.keyboardframe, text=str('='), command=self.evaluate)
            
                    b.configure(background='black', fg='white',  width=8, height=3, font = 'Helvetica 12 bold italic',cursor='hand2')
                    
                    
                if i==15:
                    
                    b=Button(self.keyboardframe, text=str('X'),command=lambda
                             arg1=b, arg2='*':
                             self.buttonPress(arg2))
            
                    b.configure(background='black', fg='white',  width=8, height=3, font = 'Helvetica 12 bold italic',cursor='hand2')
                    
                    
                    

                    
            else:

                b=Button(self.keyboardframe, text=str(i+1))
            
                b.configure(background='black', fg='white',  width=8, height=3, font = 'Helvetica 12 bold italic', cursor='hand2')
                b_count.append(b)
                
            
            if (c <=4 ):
                
                b.grid(row=r, column=c)
                c=c+1 
                
            if (c > 4) :
                c=0
                r=r+3
                b.grid(row=r, column=c)
                c=c+1
        c=1
        for i in b_count:
            
            i.bind("<Button-1>",
                   lambda
                   i,arg1=c:
                   self.buttonPress(arg1))
            
            c=c+1
        

        
    def create_entry(self):
        
        
        self.e=Label(self.topframe, background='#101010', foreground="white",borderwidth=8, relief='sunken', width=18, textvariable=self.setvalues )

        self.e.configure(font = 'Helvetica 15 bold italic')
        
        self.setvalues.set('0')


        self.e.grid(row=0,column=1,padx=2,pady=2,sticky='we',columnspan=2)
    def buttonPress(self,value):
        
        print(value)
        
        self.value=value
                       

        
            
        self.equa=self.equa+str(self.value)

        self.setvalues.set(self.equa)

    def evaluate(self):
        try:
            self.equa=str(self.equa)
            self.setvalues.set(eval (self.equa))#evaluates and displays answer
            self.equa2=self.equa
            self.equa=''
            
        except:
            print('an error occurred!!')
            
    def clearStuff(self):
        self.equa=''
        self.setvalues.set('0')
    def answer(self):
        try:
            self.setvalues.set('Ans')
            
            self.equa=str(eval(str(self.equa2)))
            
        except:
            equa=''
            
        



root=Tk()

root.geometry('380x350')
root.resizable(0,0)
root.configure(bg='#227bad')

app=calcApp(root)


app.create_buttons()

app.create_entry()


root.mainloop()
