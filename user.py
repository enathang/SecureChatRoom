from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

import json
import sys
from base64 import b64decode, b64encode

shared_secret = -1
USER_MODE = "RSA"
counter = 0
address = "A";

'''
def connect():
	msg = establishConnection()
	server_msg = send(msg)
	type, contents = parse(server_msg)
	if (type == b"INIT"):
		shared_secret, secret_dictionary = establishSharedSecret
		msg = secret_dictionary
	else if (type == b"JOIN"):
		shared_secret = parseSharedSecretDict(contents)
		msg = handshake()
	server_msg = send(msg)
	type, contents = parse(server_msg)
	if (type == "HSHK"):
		switchMode()


def read():
	server_msg = receive()
	if (USER_MODE == "AES"):
		msg_type, sender, msg, MAC, signature = decrypt_AES(server_msg, shared_secret)
		if (verifySignature(msg, signature, sender)):
			if (verifyMAC(msg, MAC)):
				plaintext = msg.decode("utf-8")





def mac(msg, counter):
	# TODO: generate MAC for msg and counter


# Message = AES{Type|MESSAGE|MAC{COUNTER}|Signature}
def write(msg):
	msg_type = b"MESG"
	plaintext = msg
	MAC = mac(msg_type+msg, counter)
	message = msg_type+plaintext+MAC
	signature = sign(message, private_key)
	enc_message = encrypt_AES(message+signature, shared_secret)

	send(enc_message)


def disconnect():
	msg = dropConnection()
	send(msg)


def switchMode():
	if (USER_MODE == "RSA"):
		USER_MODE = "AES"
	else:
		USER_MODE = "RSA"


def establishConnection():
	# Message
	message_type = b"JOIN"
	public_key_string = public_key.export_key()
	message = message_type+public_key_string
	signature = sign(message, private_key)

	return message+signature


def dropConnection():
	# Message
	message_type = b"LEAV"
	public_key_string = public_key.export_key()
	message = message_type+public_key_string

	# Signature
	h = SHA256.new(message)
	signature = pkcs1_15.new(private_key).sign(h)

	return message+signature
'''
def sign(message, private_key):
	h = SHA256.new(message)
	signature = pkcs1_15.new(private_key).sign(h)

	return signature

def encrypt_AES(message, key):
    cipher_aes = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message)

    return ciphertext, cipher_aes.nonce, tag

def getPublicKey(address):
	key_file = "keys/"+address+"_pub.pem"
	with open(key_file) as f:
		key = RSA.import_key(f.read())

	return key


def decrypt_AES(message, key):
    tag = message[-16:]
    msg_nonce = message[-32:-16]
    ciphertext = message[:-32]

    cipher_aes = AES.new(key, AES.MODE_EAX, msg_nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return plaintext



def generateSharedSecretDict(users_publickeys, session_key):
	secrets_dict = dict()

	for user_publickey in users_publickeys:
		user_key = user_publickey
		cipher_rsa = PKCS1_OAEP.new(user_key)
		enc_session_key = cipher_rsa.encrypt(session_key)
		secrets_dict[str(user_publickey.export_key())] = b64encode(enc_session_key).decode('utf-8')

	return secrets_dict


def verifySignature(message, signature, key):
	h = SHA256.new(message)
	try:
	    pkcs1_15.new(key).verify(h, signature)
	    #print "The signature is valid."
	    return True
	except (ValueError, TypeError):
	 	#print "The signature is not valid."
	 	return False



def parseSharedSecretDict(secrets_dict):
	enc_session_key = b64decode(secrets_dict[str(public_key.export_key())].encode('utf-8'))
	cipher_rsa = PKCS1_OAEP.new(private_key)
	session_key = cipher_rsa.decrypt(enc_session_key)

	return session_key


def generateUserKeys():
	key = RSA.generate(2048)
	private_key_object = key.export_key()
	public_key_object = key.publickey().export_key()
	public_key = RSA.import_key(public_key_object)
	private_key = RSA.import_key(private_key_object)

	return public_key, private_key


def exportKeys():
	file_out = open("receiver.pem", "wb")
	file_out.write(public_key)
	file_out = open("private.pem", "wb")
	file_out.write(private_key)



def establishSharedSecret(users_publickeys):
	session_key = get_random_bytes(16)
	secret_dictionary = generateSharedSecretDict(users_publickeys, session_key)
	json_secret_dictionary = json.dumps(secret_dictionary)

	return session_key, json_secret_dictionary

def parseNewSecretMessage(msg_content):
	secrets_dict = json.loads(msg_content)
	shared_secret = parseSharedSecretDict(secrets_dict)


def parseTextMessage(msg_content):
	plaintext = ""
	# plaintext = decrypt_aes(msg_content, sharedsecret)
	return plaintext

''' HIGH LEVEL API '''
signature_length = 256
def receiveAndParseMessage(message):
	msg_type = int(message[0:1].decode('ascii'))
	msg_address = message[1:2].decode('ascii')
	msg_content = message[2:-signature_length].decode('ascii')
	signature = message[-signature_length:]
	msg_public_key = getPublicKey(msg_address)

	isValidSignature = verifySignature(message[0:-signature_length], signature, msg_public_key) # shoud be address
	if (not isValidSignature):
		return -1, ""

	ret = ""
	if (msg_type == 1): # Join message
		print ("Message type 1")
		# Do nothing because the client should never receive this type of message
	elif (msg_type == 2): # Init message
		print ("Message type 2")
		ret = parseInitMessage(message) # Return a message of shared secret dict
	elif (msg_type == 3): # New shared secret message
		print ("Message type 3")
		ret = parseNewSecretMessage(msg_content) # Don't return anything
	elif (msg_type == 4): # Leave message
		print ("Message type 4")
		# Do nothing because the client should never receive this type of message
	elif (msg_type == 5): # Encrypted text message
		print ("Message type 5")
		ret = parseTextMessage(message) # Return plaintext
	else:
		print ("Unrecognized message type: " + str(msg_type))
		return -1, ""

	return msg_type, ret

def generateJoinMessage():
	msg_type = "1".encode('ascii')
	sent_from = address.encode('ascii')
	message = msg_type + sent_from

	signature = sign(message, private_key)

	return message + signature


def generateSharedSecretDictMessage(receipients):
	msg_type = "3".encode('ascii')
	sent_from = address.encode('ascii')
	secret, json_dict = establishSharedSecret(receipients) # Note dict is sent unencrypted
	message = msg_type + sent_from + json_dict.encode('ascii')

	signature = sign(message, private_key)

	return message + signature


def generateLeaveMessage():
	msg_type = "4".encode('ascii')
	sent_from = address.encode('ascii')
	message = msg_type + sent_from

	signature = sign(message, private_key)

	return message + signature


def generateTextMessage(plaintext):
	msg_type = "5".encode('ascii')
	sent_from = address.encode('ascii')
	ciphertext, msg_nonce, tag = encrypt_AES(plaintext, shared_secret)
    msg_body = ciphertext + msg_nonce + tag
	message = msg_type + sent_from + msg_body

	signature = sign(message, private_key)

	return message + signature


public_key, private_key = generateUserKeys()
session_key = get_random_bytes(16)
d = generateSharedSecretDictMessage([public_key])
# print(d)
receiveAndParseMessage(d)
