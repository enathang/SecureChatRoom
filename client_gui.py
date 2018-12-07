from Tkinter import *
import interface_functions

import user 

class client_gui:
	class chat_gui(netif):
		def receive(netif):
			"""Handles receiving of messages."""
			while True:
				status, enc_msg = netif.receive_msg(blocking=True)

		def send(event=None):  # event is passed by binders.
			"""Handles sending of messages."""
			msg = my_msg.get()
			my_msg.set("")  # Clears input field.
			## build enc message to send then call send functions

			if msg == "{quit}":
        		
        		top.quit()


		def on_closing(event=None):
			"""This function is to be called when the window is closed."""
    		my_msg.set("{quit}")
			send()

		top = tkinter.Tk()
		top.title("CsippCsapp")

		messages_frame = tkinter.Frame(top)
		my_msg = tkinter.StringVar()  # For the messages to be sent.
		my_msg.set("Type your messages here.")
		scrollbar = tkinter.Scrollbar(messages_frame)  # To navigate through past messages.

		msg_list = tkinter.Listbox(messages_frame, height=15, width=50, yscrollcommand=scrollbar.set)
		scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
		msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
		msg_list.pack()

		messages_frame.pack()

		entry_field = tkinter.Entry(top, textvariable=my_msg)
		entry_field.bind("<Return>", send)
		entry_field.pack()
		send_button = tkinter.Button(top, text="Send", command=send)
		send_button.pack()

		top.protocol("WM_DELETE_WINDOW", on_closing)