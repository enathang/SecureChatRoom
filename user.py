from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


shared_secret = -1
USER_MODE = "RSA"
counter = 0


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


def sign(message, private_key):
	h = SHA256.new(message)
	signature = pkcs1_15.new(private_key).sign(h)

	return signature


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


def encrypt_AES(message, key):
	cipher_aes = AES.new(key, AES.MODE_EAX)
	ciphertext, tag = cipher_aes.encrypt_and_digest(message)

	return ciphertext, tag, cipher_aes.nonce


def decrypt_AES(message, key):
	cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
	data = cipher_aes.decrypt_and_verify(ciphertext, tag)

	msg_type = data[:16]
	msg = data[16:-32]
	MAC = data[-32:-16]
	signature = data[-16:]

	return msg_type, msg, MAC, signature


def establishSharedSecret(users_publickeys):
	session_key = get_random_bytes(16)
	secret_dictionary = generateSharedSecretDict(users_publickeys, session_key)

	return session_key, secret_dictionary


def generateSharedSecretDict(users_publickeys, session_key):
	secrets_dict = dict()

	for user_publickey in users_publickeys:
		user_key = user_publickey
		cipher_rsa = PKCS1_OAEP.new(user_key)
		enc_session_key = cipher_rsa.encrypt(session_key)
		secrets_dict[user_publickey.export_key()] = enc_session_key

	return secrets_dict


def verifySignature(message, signature, key):
	h = SHA.new(message)
	try:
	    pkcs1_15.new(key).verify(h, signature):
	    #print "The signature is valid."
	    return True
	except (ValueError, TypeError):
	 	#print "The signature is not valid."
	 	return False



def parseSharedSecretDict(secrets_dict):
	enc_session_key = secrets_dict[public_key.export_key()]
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

# Codes: INIT, JOIN, MESG, LEAV, HSHK
public_key, private_key = generateUserKeys()
session_key = get_random_bytes(16)
print (session_key)
d = generateSharedSecretDict([public_key], session_key)
parseSharedSecretDict(d)

