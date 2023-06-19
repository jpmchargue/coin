from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from flask import Flask
import hashlib
import json
import requests
import math
import time
import random


BOOTSTRAP_NODES = [
    "208.59.107.225"
]
SERVER_PORT = 5000

def hash(string):
    data = bytes(string, 'utf-8')
    hash_algorithm = hashlib.sha256()
    hash_algorithm.update(data)
    return hash_algorithm.digest()

class Keys():
    def __init__(self, private_key):
        self.private_key = private_key
    def generate_new_pair():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        return Keys(private_key)
    def sign(self, string):
        return self.private_key.sign(
            bytes(string, 'utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    def public_key(self):
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    def verify_signature(string, signature, public_key):
        public_key_obj = serialization.load_pem_public_key(public_key)
        try:
            public_key_obj.verify(
                signature,
                bytes(string, 'utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            return False
        else:
            return True

class Outpoint():
    def __init__(self, previous_tx_id, previous_tx_output_index, previous_tx_output_recipient, previous_tx_output_value):
        self.previous_tx_id = previous_tx_id
        self.previous_tx_output_index = previous_tx_output_index
        self.previous_tx_output_recipient = previous_tx_output_recipient
        self.previous_tx_output_value = previous_tx_output_value

class TxIn():
    def __init__(self, outpoint, signature):
        self.previous_tx_id = outpoint.previous_tx_id
        self.previous_tx_output_index = outpoint.previous_tx_output_index
        self.signature = signature

class TxOut():
    def __init__(self, amount, recipient):
        self.amount = amount
        self.recipient = recipient

class Transaction():
    def __init__(self, inputs, outputs):
        self.id = random.randbytes(64)
        self.inputs = inputs
        self.outputs = outputs
        self.time = math.floor(time.time())

    def create(keys, previous_tx_id, previous_tx_output_index, previous_tx_value, recipient, amount):
        signature = keys.sign(str(previous_tx_id) + str(previous_tx_output_index))
        inputs = [TxIn(previous_tx_id, previous_tx_output_index, signature)]
        outputs = [TxOut(amount, recipient), TxOut(previous_tx_value - amount, keys.public_key())]
        return Transaction(inputs, outputs)

    def verify_transaction(transaction, blockchain):
        # Transaction must not already exist
        if blockchain.get_transaction(transaction.id) is not None:
            return False

        outpoints = [blockchain.get_outpoint(ti.previous_tx_id, ti.previous_tx_output_index) for ti in transaction.inputs]
        total_input_value = 0

        for i in range(len(transaction.inputs)):
            ti = transaction.inputs[i]
            op = outpoints[i]

            # Transaction input signatures must be valid
            input_is_valid = Keys.verify_signature(
                str(ti.previous_tx_id) + str(ti.previous_tx_output_index),
                ti.signature,
                op.previous_tx_output_recipient
            )
            if not input_is_valid:
                return False
        
            # Transaction inputs cannot be double spent
            if blockchain.is_spent(op):
                return False

            total_input_value += op.previous_tx_output_value

        # Total transaction input value must equal output value
        total_output_value = sum([to.amount for to in transaction.outputs])
        if total_input_value != total_output_value:
            return False

        return True

    

class Block():
    def __init__(self):
        self.transactions = []

    def from_json(json):
        # create a block from json
        pass

    def add_transaction(self, transaction):
        pass



class Blockchain():
    def __init__(self):
        self.blocks = []

    def add_block(self, block):
        self.blocks.append(block)


class Node():
    def __init__(self):
        self.peers = BOOTSTRAP_NODES
        self.port = SERVER_PORT

    def request(self, ip, json=None):
        if json is None:
            # GET request
            requests.get(ip, self.port)
        

    def broadcast(self, content):
        pass

    def bootstrap(self):
        # populate list of peers
        pass

    def send_hello(self):
        # use broadcast
        pass

    def send_transaction(self, transaction):
        # use broadcast
        pass

    def accept_block(self, block):
        # add a block to the blockchain and cancel any mining on the current block
        # start a new block
        pass

    def send_block(self, block):
        pass

    def start_mining(self):
        pass

    def handle_transaction(self, transaction):
        # check if a transaction is valid, and add it if so
        pass

    def handle_block(self, block):
        # check if a block is valid, and add it if so
        pass

    def mine(self):
        # start a background thread running this function as a process.
        # run a loop where a nonce is created and tested, and if its hash
        # has a certain number of zeros, broadcast it.


app = Flask(__name__)

@app.route("/hello")
def hello():
    """
    Add the requesting IP to this server's list of peers.
    """
    pass

@app.route("/blockchain")
def get_blockchain():
    """
    Return a copy of the entire blockchain, according to this node.
    """
    return "<p>Hello, World!</p>"

@app.route("/block")
def get_current_block():
    pass

@app.route("/post/block")
def receive_block(data):
    pass

@app.route("/post/transaction")
def receive_transaction(data):
    pass

@app.route("/user")
def get_user():
    # get all transactions associated with a user, using their public key
    pass

@app.route("/transaction")
def get_transaction():
    # use transaction hash?
    pass