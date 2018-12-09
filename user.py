from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
from chat_protocol import MsgType
from pathlib import Path
from netinterface import network_interface

import os
import json
import sys
from base64 import b64decode, b64encode

shared_secret = -1
USER_MODE = "RSA"
counter = 0
global address
address = "A";
global session_key
session_key = b''

global private_key
global public_key
global _netif

def init_user(addr):
    global address
    global private_key
    global public_key
    global _netif
    address = addr
    public_key = getPublicKey(addr)
    private_key = get_private_key(addr)
    _netif = network_interface('./', address)

def sign(message, private_key):
	h = SHA256.new(message)
	signature = PKCS1_PSS.new(private_key).sign(h)

	return signature


def encrypt_AES(message, key):
	#if(key == -1):
	#	print('Cannot encrypt text before shared secret is established.')
	cipher_aes = AES.new(key, AES.MODE_EAX)
	ciphertext, tag = cipher_aes.encrypt_and_digest(message)
	return ciphertext, cipher_aes.nonce, tag


def getPublicKey(address):
	key_file = "keys/"+address+"_pub.pem"
	with open(key_file) as f:
		key = RSA.import_key(f.read())

	return key

def get_private_key(address):
	key_file = "keys/"+address+"_priv.pem"
	with open(key_file) as f:
		key = RSA.import_key(f.read())
	return key

def decrypt_AES(message, key):
	#if(key == -1):
	#	print('Cannot encrypt text before shared secret is established.')
	tag = message[-16:]
	msg_nonce = message[-32:-16]
	ciphertext = message[:-32]
	print('tag: ', tag, '\nnonce: ', msg_nonce, '\nciphertext: ', ciphertext)
	cipher_aes = AES.new(key, AES.MODE_EAX, msg_nonce)
	plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
	return plaintext


def generateSharedSecretDict(user_list):
    secrets_dict = dict()

    for usr in user_list:
        with open('./keys/' + usr +'_pub.pem', 'r') as usr_kfile:
            usr_kstr = usr_kfile.read()
            user_key = RSA.import_key(usr_kstr)
            cipher_rsa = PKCS1_OAEP.new(user_key)
            enc_session_key = cipher_rsa.encrypt(session_key)
            secrets_dict[usr] = b64encode(enc_session_key).decode('ascii')
    return secrets_dict


def generateSharedSecretString(user_list):
	byte_str = b""

	for usr in user_list:
		with open('./keys/' + usr +'_pub.pem', 'r') as usr_kfile:
			usr_kstr = usr_kfile.read()
			user_key = RSA.import_key(usr_kstr)
			cipher_rsa = PKCS1_OAEP.new(user_key)
			enc_session_key = cipher_rsa.encrypt(session_key)
			byte_str += enc_session_key
	return byte_str


def verifySignature(message, signature, key):
	h = SHA256.new(message)
	try:
	    PKCS1_PSS.new(key).verify(h, signature)
	    #print "The signature is valid."
	    return True
	except (ValueError, TypeError):
	 	#print "The signature is not valid."
	 	return False


def parseSharedSecretString(msg):
	global session_key
	user_order = msg[0:5].decode('ascii')
	user_index = user_order.index(address)

	enc_session_key = msg[5+user_index*256:5+(user_index+1)*256]
	cipher_rsa = PKCS1_OAEP.new(private_key)
	session_key = cipher_rsa.decrypt(enc_session_key)
	return session_key


def parseSharedSecretDict(secrets_dict):
	enc_session_key = b64decode(secrets_dict[address].encode('ascii'))
	cipher_rsa = PKCS1_OAEP.new(private_key)
	session_key = cipher_rsa.decrypt(enc_session_key)
	return session_key


def establishSharedSecret(users_list):
    print('establishin...')
    global session_key
    #session_key = get_random_bytes(16)
    secret_dictionary = generateSharedSecretDict(users_list)
    print(secret_dictionary)
    json_secret_dictionary = b64encode(json.dumps(secret_dictionary).encode('ascii'))

    return session_key, json_secret_dictionary

def establishSharedSecretString(user_list):
    print('establishin...')
    global session_key
    session_key = get_random_bytes(16)
    secret_string = generateSharedSecretString(user_list)
    user_list_bytes = user_list.encode('ascii')

    return session_key, user_list_bytes+secret_string


def parseNewSecretMessage(msg_content):
    if verify_message_freshness(msg_content):
        print('verified correctly.')
        shared_secret = parseSharedSecretString(msg_content[2:-signature_length])

def parseTextMessage(msg_content):
	msg_body = msg_content[2:-signature_length]
	plaintext = decrypt_AES(msg_body, session_key)
	return plaintext.decode('ascii')

''' HIGH LEVEL API '''
signature_length = 256
def receiveAndParseMessage(message): # Make this just a fixed thing
	print('Received and parsing message: ', message)
	msg_type = int(message[0:1].decode('ascii'))
	msg_address = message[1:2].decode('ascii')
	signature = message[-signature_length:]
	msg_public_key = getPublicKey(msg_address)

	isValidSignature = verifySignature(message[0:-signature_length], signature, msg_public_key) # shoud be address
	if (not isValidSignature):
		print ("Is not valid signature")
		return -1, b""

	ret = ""
	if (msg_type == MsgType.JOIN): # Join message
		print ("Message type JOIN")
		# Do nothing because the client should never receive this type of message
	elif (msg_type == MsgType.INIT): # Init message
		print ("Message type INIT")
		ret = generateSharedSecretDictMessage() # Return a message of shared secret dict
	elif (msg_type == MsgType.SECRET): # New shared secret message
		print ("Message type SECRET")
		ret = parseNewSecretMessage(message)
	elif (msg_type == MsgType.LEAVE): # Leave message
		print ("Message type LEAVE")
		# Do nothing because the client should never receive this type of message
	elif (msg_type == MsgType.MSG): # Encrypted text message
		print ("Message type MSG")
		ret = parseTextMessage(message) # Return plaintext
	else:
		print ("Unrecognized message type: " + str(msg_type))
		return -1, ""

	return msg_type, ret

def generateJoinMessage():
	msg_type = str(int(MsgType.JOIN)).encode('ascii')
	sent_from = address.encode('ascii')
	message = msg_type + sent_from

	signature = sign(message, private_key)
	return message + signature



def verify_message_freshness(test_msg):
    print('verifyin secret freshness')
    msg, nonce = generateChallengeMessage(test_msg)
    _netif.send_msg('S', msg)

    # Drop racey messages
    status, response = _netif.receive_msg(blocking=True)
    while(response[0] != ord(str(int(MsgType.CHALLENGE)).encode('ascii'))):
        status, response = _netif.receive_msg(blocking=True)
    return challenge_response_verify(response, nonce)

def generateChallengeMessage(msg):
    print('generatin challenge message')
    hash = SHA256.new(msg).digest()

    msg_type = str(int(MsgType.CHALLENGE)).encode('ascii')
    sent_from = address.encode('ascii')
    nonce = get_random_bytes(16)

    cipher = PKCS1_OAEP.new(getPublicKey('S'))
    message_body = cipher.encrypt(nonce+hash)
    message = str(int(MsgType.CHALLENGE)).encode('ascii') + address.encode('ascii') + message_body
    signature = sign(message, private_key)
    return message + signature, nonce

def challenge_response_verify(message, expected_nonce):
        print('verifyin challenge response')
        if verifySignature(message[:-signature_length], message[-signature_length], getPublicKey('S')):
            msg_body = message[2:-256]
            cipher = PKCS1_OAEP.new(private_key)
            plaintext = cipher.decrypt(msg_body)
            if(plaintext == expected_nonce):
                return True
        return False

def generateSharedSecretDictMessage():
	msg_type = str(int(MsgType.SECRET)).encode('ascii')
	sent_from = address.encode('ascii')
	secret, string = establishSharedSecretString('ABCDE') # Note dict is sent unencrypted
	message = msg_type + sent_from + string

	signature = sign(message, private_key)

	return message + signature


def generateLeaveMessage():
	msg_type = str(int(MsgType.LEAVE)).encode('ascii')
	sent_from = address.encode('ascii')
	message = msg_type + sent_from

	signature = sign(message, private_key)

	return message + signature


def generateTextMessage(plaintext):
	plaintext = plaintext.encode('ascii') if not type(plaintext) == bytes else plaintext
	msg_type = str(int(MsgType.MSG)).encode('ascii')
	sent_from = address.encode('ascii')
	ciphertext, msg_nonce, tag = encrypt_AES(plaintext, session_key)
	msg_body = ciphertext + msg_nonce + tag
	message = msg_type + sent_from + msg_body

	signature = sign(message, private_key)
	print('Sending message: \n', message+signature)
	return message + signature
