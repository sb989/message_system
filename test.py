from tkinter import *
import threading





def gui():
    root = Tk()
    scrollbar = Scrollbar(root)
    scrollbar.pack( side = RIGHT, fill = Y )
    mylist = Listbox(root, yscrollcommand = scrollbar.set )
    #for line in range(100):
       #mylist.insert(END, 'This is line number' + str(line))
    mylist.pack( side = LEFT, fill = BOTH )
    scrollbar.config( command = mylist.yview )
    root.mainloop()
    mylist.insert(END, 'This is line number')


#gui(root)
#root = Tk()
threading.Thread(target=gui,args=()).start()
#while True:
