from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
from chat_protocol import MsgType

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

def init_user(addr):
    global address
    address = addr

def sign(message, private_key):
	h = SHA256.new(message)
	signature = PKCS1_PSS.new(private_key).sign(h)

	return signature


def encrypt_AES(message, key):
    if(key == -1):
        print('Cannot encrypt text before shared secret is established.')
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
    if(key == -1):
        print('Cannot encrypt text before shared secret is established.')
    tag = message[-16:]
    msg_nonce = message[-32:-16]
    ciphertext = message[:-32]
#DEBUG    print('tag: ', tag, '\nnonce: ', msg_nonce, '\nciphertext: ', ciphertext)
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
            secrets_dict[usr] = b64encode(enc_session_key).decode('utf-8')

    return secrets_dict


def verifySignature(message, signature, key):
	h = SHA256.new(message)
	try:
	    PKCS1_PSS.new(key).verify(h, signature)
	    #print "The signature is valid."
	    return True
	except (ValueError, TypeError):
	 	#print "The signature is not valid."
	 	return False



def parseSharedSecretDict(secrets_dict):
	enc_session_key = b64decode(secrets_dict[address]).encode('utf-8')
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


def establishSharedSecret(users_list):
    print('establishin...')
    global session_key
    session_key = get_random_bytes(16)
    secret_dictionary = generateSharedSecretDict(users_list)
    json_secret_dictionary = json.dumps(secret_dictionary)

    return session_key, json_secret_dictionary


def parseNewSecretMessage(msg_content):
	secrets_dict = json.loads(msg_content)
	shared_secret = parseSharedSecretDict(secrets_dict)


def parseTextMessage(msg_content):
    msg_body = msg_content[2:-256]
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
		return -1, ""

	ret = ""
	if (msg_type == MsgType.JOIN): # Join message
		print ("Message type JOIN")
		# Do nothing because the client should never receive this type of message
	elif (msg_type == MsgType.INIT): # Init message
		print ("Message type INIT")
		ret = generateSharedSecretDictMessage() # Return a message of shared secret dict
	elif (msg_type == MsgType.SECRET): # New shared secret message
		print ("Message type SECRET")
		ret = parseNewSecretMessage(message[2:-signature_length].decode('ascii'))
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


def generateSharedSecretDictMessage():
	msg_type = str(int(MsgType.SECRET)).encode('ascii')
	sent_from = address.encode('ascii')
	secret, json_dict = establishSharedSecret('ABCDE') # Note dict is sent unencrypted
	message = msg_type + sent_from + json_dict.encode('ascii')

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
	print('Sending message: \n', message)
	return message + signature


public_key = getPublicKey(address)
private_key = get_private_key(address)
# session_key = get_random_bytes(16)
