from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
from enum import Enum

from netinterface import network_interface
from chat_protocol import MsgType
import chat_protocol
import random

SERVER_ADDR = 'S'

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
        self.state = ServerState.UNINITIALIZED

    def listen():
        while True:
            status, msg = netif.receive_msg(blocking=True)
            evaluate_msg(msg)

    def evaluate_msg(msg):
        try:
            msg_type = int(msg[:chat_protocol.MSG_TYPE_SIZE])
        except ValueError:
            error('Invalid msg_type received. Dropping message.')
            return
        if not validate(msg):
            error('Message did not validate correctly.')
            return
        msg_source = msg[1:2].encode('utf-8')[0]
        try:
            opts  = {
                MsgType.JOIN       : response_join,
                #    MsgType.INIT       : response_init,
                MsgType.LEAVE      : response_leave,
                MsgType.MESSAGE    : response_msg,
                MsgType.SECRET     : response_secret
                }[msg_type](msg, msg_source)
        except KeyError:
            error('Invalid msg_type received. Dropping message.')
            return

    def destroy(self):
        for usr in self.group_members:
            self.group_members[usr] = False
        self.state = ServerState.UNINITIALIZED

    def validate(self, msg):
        try:
            usr = msg[1:2]
            with open(usr +'.pem', r) as usr_kfile:
                usr_kstr = usr_kfile.read()
                usr_sig = msg[-SIGNATURE_SIZE:]
                verify_signature(msg[:-SIGNATURE_SIZE], usr_sig, usr_kstr)
        except:
            return False

    def response_join(msg, msg_source):
        send_init(msg_source)

    def response_leave(msg, msg_source):
        # We already have verified that the user exists (so no need to check for KeyError)
        try:
            self.group_members[msg_source] = False
            if(reduce( lambda x, y), self.group_members[msg_source])
            new_initiator = random.choice(list(self.group_members))
            send_init(new_initiator)
        except KeyError:
            error('key error in leave response -- specified group member not found!')
            return

    def response_msg(msg, msg_source):
        forward_msg(msg, msg_source)

    def response_secret(msg, msg_source):
        forward_msg(msg, msg_source)

    def forward_msg(msg, msg_source):
        dest_addresses = ''.join(
            [dest for dest in self.group_members if self.group_members[dest]]
            )
        send_msg(msg, data_addresses)

    def send_msg(msg, data_addresses):
        # send message, but with appropriate server wrappings (id in the front, and then siggy in the back!
        msg = msg + SERVER_ADDR
        hash = SHA.new(msg)
        signature = signer.sign(hash)
        msg = msg + signature
        netif.send(msg)

def verify_signature(message, signature, key):
        h = SHA.new(message)
        try:
            PKCS1_PSS.new(k).verify(h, signature):
            return True
        except (ValueError, TypeError):
            return False
