#!/usr/bin/env python3
#interface_functions.py

import os, sys, getopt, time
from netinterface import network_interface

from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
from enum import Enum

from chat_protocol import MsgType
import chat_protocol


#import user

import tkinter
from threading import Thread

NET_PATH = './'
OWN_ADDR = 'A'
SERVER = 'S'

# ------------       
# main program
# ------------

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:', longopts=['help', 'path=', 'addr='])
except getopt.GetoptError:
	print('Usage: python client_interface.py -p <network path> -a <own addr>')
	sys.exit(1)

for opt, arg in opts:
	if opt == '-h' or opt == '--help':
		print('Usage: python client_interface.py -p <network path> -a <own addr>')
		sys.exit(0)
	elif opt == '-p' or opt == '--path':
		NET_PATH = arg
	elif opt == '-a' or opt == '--addr':
		OWN_ADDR = arg

if (NET_PATH[-1] != '/') and (NET_PATH[-1] != '\\'): NET_PATH += '/'

if not os.access(NET_PATH, os.F_OK):
	print('Error: Cannot access path ' + NET_PATH)
	sys.exit(1)

if len(OWN_ADDR) > 1: OWN_ADDR = OWN_ADDR[0]

if OWN_ADDR not in network_interface.addr_space:
	print('Error: Invalid address ' + OWN_ADDR)
	sys.exit(1)




# start main loop 
netif = network_interface(NET_PATH, OWN_ADDR)


## send join, recieve init, and generate new secret

	


## gui
def gui_send(event = None):
	
	msg_list.insert(tkinter.END, 'you: ' + my_msg.get())
	plain_msg = my_msg.get()
	my_msg.set('')
	## send actually send a message.
	netif.send_msg('S', plain_msg.encode('utf-8'))
	


def gui_recieve():
	while True:
		msg = netif.receive_msg(blocking=True)
		author = '' ## set this to be the author of the mes
		msg_list.insert(tkinter.END, author + ': ' + msg)


def on_closing(event=None):
	# 	netif.send_msg(SERVER, generateLeavemessage)
	top.quit()
	top.destroy()
	print('disconnected from server')
	quit()


top = tkinter.Tk()
top.title('CsippCseppCsatApp')

messages_frame = tkinter.Frame(top)
my_msg = tkinter.StringVar()
scrollbar = tkinter.Scrollbar(messages_frame)

msg_list = tkinter.Listbox(messages_frame, height=15, width=50, yscrollcommand=scrollbar.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack()

messages_frame.pack()

entry_field = tkinter.Entry(top, textvariable=my_msg)
entry_field.bind("<Return>", gui_send)
entry_field.pack()
send_button = tkinter.Button(top, text="Send", command=gui_send)
send_button.pack()

top.protocol("WM_DELETE_WINDOW", on_closing)

receive_thread = Thread(target=gui_recieve)
receive_thread.start()

tkinter.mainloop()  # Starts GUI execution.






