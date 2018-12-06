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
GROUP_ADDRESSES = b'ABCDE'

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

# main loop
netif = network_interface(NET_PATH, OWN_ADDR)

chat_server = Server(netif, 'group_members.acl', './keys/S_priv.pem')

chat_server.listen()
