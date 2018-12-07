#!/usr/bin/env python3
#interface_functions.py

from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
from enum import Enum

from chat_protocol import MsgType
import chat_protocol
import user

class interface_functions:
	
	def send(netif, msg):
		netif.send_msg('S', msg.encode('utf-8'))

	def recieve(netif):
		status , msg = netif.recieve_msg(blocking=True)
		return msg
		#evaluate_msg(msg)
	
	#def evaluate_msg(msg):
