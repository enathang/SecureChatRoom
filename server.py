#server
import os, sys, getopt, time
from netinterface import network_interface
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

from server_func import Server

NET_PATH = './'
OWN_ADDR = 'S'
GROUP_ADDRESSES = 'ABCDE'

# ------------
# main program
# ------------

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:', longopts=['help', 'path=', 'addr='])
except getopt.GetoptError:
	print('Usage: python server.py -p <network path> -a <own addr> ')
	sys.exit(1)

for opt, arg in opts:
	if opt == '-h' or opt == '--help':
		print('Usage: python server.py -p <network path> -a <own addr> ')
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

#server functions
#forwards the message provided it was not the message previously forwarded.
def forward(msg, prev_msg):
	if not msg == prev_msg:
		netif.send_msg(GROUP_ADDRESSES, msg)
	prev_msg = msg
	return prev_msg
#sends a message provided it hasn't already been sent.
def send(dst, msg, prev_msg):
	if not msg == prev_msg:
		netif.send_msg(dst, msg)
	prev_msg = msg
	return prev_msg

# main loop
netif = network_interface(NET_PATH, OWN_ADDR)
chat_server = Server(netif, 'group_members.acl', 'server_sec.pem')

chat_server.listen()


'''
prev_msg = ''
msg_type = ''
print('Main loop started...')
while True:
# Calling receive_msg() in non-blocking mode ...
#	status, msg = netif.receive_msg(blocking=False)
#	if status: print(msg)      # if status is True, then a message was returned in msg
#	else: time.sleep(2)        # otherwise msg is empty

# Calling receive_msg() in blocking mode ...
	status, msg = netif.receive_msg(blocking=True)      # when returns, status is True and msg contains a message

	msg_type = msg[:4].decode('utf-8')

	if msg_type ==  'INIT':
		## reply with init message
		msg = #init
		prev_msg = send(dst, msg, prev_msg)
	elif msg_type == 'JOIN':
		## reply with the join response
		msg = #join
		send(dst, msg, prev_msg)
	elif msg_type == 'MESG':
		## forward encrypted message to groups
		prev_msg = forward(msg, prev_msg)
	elif msg_type == 'LEAV'
		## do leave stuff
	elif msg_type == 'HSHK':
    		##

	# to forward the recieved message to every client in the group, and only forward the message once.
	# if not msg == prev_msg:
	# 	netif.send_msg(GROUP_ADDRESSES, msg)
	# 	prev_msg = msg
    '''
