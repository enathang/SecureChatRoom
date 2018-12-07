from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
from enum import Enum
import sys

from netinterface import network_interface
from chat_protocol import MsgType
from chat_protocol import MSG_SIGNATURE_SIZE
import chat_protocol
import random

SERVER_ADDR = b'S'

class Server:
    class ServerState(Enum):
        UNINITIALIZED = 0
        INITIALIZED   = 1
    def __init__(self, netif, group_members_fname, keyfile):
        # Read in all group members, and set them to be offline
        self.group_members = {}
        with open(group_members_fname, 'r') as f:
            for line in f:
                self.group_members[line.strip()] = False
        with open(keyfile, 'r') as kfile:
            keystr = kfile.read()
            self.key_pair = RSA.import_key(keystr)
            self.dig_signer = PKCS1_PSS.new(self.key_pair)
        self.state = self.ServerState.UNINITIALIZED
        self.netif = netif

    def listen(self):
        while True:
            print('Waiting for msg...')
            status, msg = self.netif.receive_msg(blocking=True)
            self.evaluate_msg(msg)

    def evaluate_msg(self, msg):
        print('Evaluating msg...',)
        try:
            msg_type = int(msg[:chat_protocol.MSG_TYPE_SIZE])
            print('Message type: ', msg_type)
        except ValueError:
            print('Invalid msg_type received. Dropping message.', file=sys.stderr)
            return
        if not self.validate(msg):
            print('Message did not validate correctly.', file=sys.stderr)
            return

        msg_source = msg[1:2].encode('ascii')[0] if type(msg) != bytes else msg[1:2]
        try:
            opts  = {
                MsgType.JOIN       : self.response_join,
                MsgType.LEAVE      : self.response_leave,
                MsgType.MSG        : self.response_msg,
                MsgType.SECRET     : self.response_secret
                }[msg_type](msg, msg_source)
        except KeyError:
            print('Invalid msg_type received. Dropping message.', file=sys.stderr)
            return

    def destroy(self):
        print('Server resetting...')
        for usr in self.group_members:
            self.group_members[usr] = False
        self.state = ServerState.UNINITIALIZED

    def validate(self, msg):
        print('Validating msg...\n', msg[:-MSG_SIGNATURE_SIZE])
        try:
            usr = msg[1:2].decode('ascii')
            with open('./keys/' + usr +'_pub.pem', 'r') as usr_kfile:
                usr_kstr = usr_kfile.read()
                usr_key = RSA.import_key(usr_kstr)

                usr_sig = msg[-MSG_SIGNATURE_SIZE:]
                verify_signature(msg[:-MSG_SIGNATURE_SIZE], usr_sig, usr_key)
                return True
        except SyntaxError:
            return False

    def response_join(self, msg, msg_source):
        print('Responding to join message...')
        self.group_members[msg_source.decode()] = True
        self.send_init(msg_source)

    def response_leave(self, msg, msg_source):
        print('Responding to leave message...')
        # We already have verified that the user exists (so no need to check for KeyError)
        try:
            self.group_members[msg_source] = False
            if(len([x for x in self.group_members if self.group_members[x]]) != 0):
                self.destroy()
            new_initiator = random.choice(list(self.group_members))
            self.send_init(new_initiator)
        except KeyError:
            print('key error in leave response -- specified group member not found!', file=sys.stderr)
            return

    def response_msg(self, msg, msg_source):
        print('Responding to text message...')
        self.forward_msg(msg, msg_source)

    def response_secret(self, msg, msg_source):
        print('Responding to secret message...')
        self.forward_msg(msg, msg_source)

    def forward_msg(self, msg, msg_source):
        print('Forwarding message from ', msg_source)
        try:
            dest_addresses = ''.join(
                [dest for dest in self.group_members if self.group_members[dest] and dest != msg_source.decode()]
                )
            self.send_msg(msg, dest_addresses)
        except:
            print('Client not found, message not forwarded? Client: ', self.group_members)


    def send_msg(self, msg, data_addresses):
        print('Sending message to ', data_addresses)
        # Below commented line if we want server wrapping messages with its own addr/sig combo
        msg = self.format_msg(msg)
        data_addresses = data_addresses.decode() if type(data_addresses) == bytes else data_addresses
        self.netif.send_msg(data_addresses, msg)

    def format_msg(self, msg):
        msg = msg + SERVER_ADDR
        hash = SHA256.new(msg)
        signature = self.dig_signer.sign(hash)
        msg = msg + signature
        return msg

    def send_init(self, usr):
#        msg_type = bytes([MsgType.INIT])
        print('Received msg from', usr, 'Sending init...\n')
        msg_type = str(int(MsgType.INIT)).encode('ascii')
        msg = self.format_msg(msg_type)
        self.send_msg(msg, usr)

def verify_signature(message, signature, key):
        h = SHA256.new(message)
        print(message, key)
        try:
            PKCS1_PSS.new(key).verify(h, signature)
            return True
        except SyntaxError:
            return False
