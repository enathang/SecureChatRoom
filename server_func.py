from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
from enum import Enum
import sys

from netinterface import network_interface
from chat_protocol import MsgType
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
        with open(group_members_fname, 'rb') as f:
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
            status, msg = self.netif.receive_msg(blocking=True)
            self.evaluate_msg(msg)

    def evaluate_msg(self, msg):
        try:
            msg_type = int(msg[:chat_protocol.MSG_TYPE_SIZE])
        except ValueError:
            print('Invalid msg_type received. Dropping message.', file=sys.stderr)
            return
        if not self.validate(msg):
            print('Message did not validate correctly.', file=sys.stderr)
            return
        msg_source = msg[1:2].encode('ascii')[0]
        try:
            opts  = {
                MsgType.JOIN       : response_join,
                MsgType.LEAVE      : response_leave,
                MsgType.MESSAGE    : response_msg,
                MsgType.SECRET     : response_secret
                }[msg_type-1](msg, msg_source)
        except KeyError:
            print('Invalid msg_type received. Dropping message.', file=sys.stderr)
            return

    def destroy(self):
        for usr in self.group_members:
            self.group_members[usr] = False
        self.state = ServerState.UNINITIALIZED

    def validate(self, msg):
        try:
            usr = msg[1:2]
            with open(usr +'_pub.pem', r) as usr_kfile:
                usr_kstr = usr_kfile.read()
                usr_sig = msg[-SIGNATURE_SIZE:]
                verify_signature(msg[:-SIGNATURE_SIZE], usr_sig, usr_kstr)
        except:
            return False

    def response_join(self, msg, msg_source):
        self.send_init(msg_source)

    def response_leave(self, msg, msg_source):
        # We already have verified that the user exists (so no need to check for KeyError)
        try:
            self.group_members[msg_source] = False
            if(reduce( lambda x, y: self.group_members[x] and self.group_members[y]), self.group_members):
                self.destroy()
            new_initiator = random.choice(list(self.group_members))
            self.send_init(new_initiator)
        except KeyError:
            print('key error in leave response -- specified group member not found!', file=sys.stderr)
            return

    def response_msg(self, msg, msg_source):
        self.forward_msg(msg, msg_source)

    def response_secret(self, msg, msg_source):
        self.forward_msg(msg, msg_source)

    def forward_msg(self, msg, msg_source):
        dest_addresses = ''.join(
            [dest for dest in self.group_members if self.group_members[dest]]
            )
        self.send_msg(msg, data_addresses)

    def send_msg(self, msg, data_addresses):
        # Below commented line if we want server wrapping messages with its own addr/sig combo
        #msg = self.format_msg(msg)
        self.netif.send_msg(data_addresses.decode(), msg)

    def format_msg(self, msg):
        msg = msg + SERVER_ADDR
        hash = SHA256.new(msg)
        signature = self.dig_signer.sign(hash)
        msg = msg + signature
        return msg

    def send_init(self, usr):
#        msg_type = bytes([MsgType.INIT])
        print('Received msg from', usr, 'Sending init...\n')
        msg_type = str(MsgType.INIT).encode('ascii')
        msg = format_msg(self, msg)
        self.send_msg(self, msg, usr)

def verify_signature(self, message, signature, key):
        h = SHA256.new(message)
        try:
            PKCS1_PSS.new(k).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
