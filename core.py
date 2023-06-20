from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from fastapi import FastAPI

import hashlib
import json
import requests
import math
import time
import random

import asyncio
import aiohttp


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
    def __init__(self, previous_tx_id, previous_tx_output_index, signature):
        self.previous_tx_id = previous_tx_id
        self.previous_tx_output_index = previous_tx_output_index
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

    def to_bytes(self):
        data = self.id
        for ti in self.inputs:
            data += ti.previous_tx_id + ti.previous_tx_output_index.to_bytes(1, 'big') + ti.signature
        for to in self.outputs:
            data += to.amount.to_bytes(8, 'big') + to.recipient
        data += self.time.to_bytes(8, 'big')
        return data

    def to_obj(self):
        obj_inputs = [{
            "tx_id": ti.previous_tx_id,
            "tx_output_index": ti.previous_tx_output_index,
            "signature": ti.signature
        } for ti in self.inputs]
        obj_outputs = [{
            "amount": to.amount,
            "recipient": to.recipient
        } for to in self.outputs]
        obj = {
            "id": self.id.hex(),
            "inputs": obj_inputs,
            "outputs": obj_outputs,
            "time": self.time
        }
        return obj

    def to_json(self):
        return json.dumps(self.to_obj())

    def from_obj(obj):
        inputs = [TxIn(ti["tx_id"], ti["tx_output_index"], ti["signature"]) for ti in obj["inputs"]]
        outputs = [TxOut(to["amount"], to["recipient"]) for to in obj["outputs"]]
        transaction = Transaction(inputs, outputs)
        transaction.id = obj["id"]
        transaction.time = obj["time"]
        return transaction

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
    def __init__(self, index, previous_hash, nonce=0, transactions=[], time=0):
        self.index = index # int
        self.previous_hash = previous_hash # bytes
        self.nonce = nonce # bytes
        self.transactions = transactions # List(Transaction)
        self.time = time # int

    def from_copy(block):
        return Block(
            block.index, 
            block.previous_hash, 
            nonce=block.nonce, 
            transactions=block.transactions[:], 
            time=math.floor(time.time())
        )

    def from_json(json):
        # create a block from json
        pass

    def to_obj(self):
        obj_transactions = [tx.to_obj() for tx in self.transactions]
        obj = {
            "index": self.index,
            "previous_hash": self.previous_hash.hex(),
            "nonce": self.nonce.hex(),
            "transactions": obj_transactions,
            "time": self.time
        }
        return obj

    def to_json(self):
        return json.dumps(self.to_obj())

    def from_obj(obj):
        transactions = [Transaction.from_obj(tx) for tx in obj["transactions"]]
        block = Block(
            block["index"], 
            bytes.fromhex(block["previous_hash"]),
            bytes.fromhex(obj["nonce"]),
            transactions,
            block["time"]
        )
        return block

    def add_transaction(self, transaction):
        self.transactions.append(transaction)

    def check_nonce(self, nonce):
        data = self.index.to_bytes(4, 'big') + self.previous_hash + nonce
        for tx in self.transactions:
            data += tx.to_bytes()
        data += self.time.to_bytes(8, 'big')

        return hash(data)    



class Blockchain():
    def __init__(self):
        self.blocks = []
        self.current_block = None

    def add_block(self, block):
        self.blocks.append(block)

    def to_obj(self):
        obj_blocks = [b.to_obj() for b in self.blocks]
        obj = {
            "blocks": obj_blocks
        }
        return obj

    def to_json(self):
        return json.dumps(self.to_obj())

    def from_obj(obj):
        blockchain = Blockchain()
        blockchain.blocks = [Block.from_obj(block) for block in obj["blocks"]]
        return blockchain



class Node():
    def __init__(self):
        self.peers = BOOTSTRAP_NODES
        self.port = SERVER_PORT
        self.blockchain = Blockchain()

    #def request(self, ip, json=None):
    #    if json is None:
            # GET request
            #requests.get(ip, self.port)
        

    #def broadcast(self, content):
    #    pass

    def bootstrap(self):
        # populate list of peers
        peers_json = requests.get(random.choice(BOOTSTRAP_NODES) + "/peers")
        self.peers = json.loads(peers_json)

    def update_peers(self):
        peers_json = requests.get(random.choice(self.peers) + "/peers")
        self.peers = json.loads(peers_json)

    def request_user_data(self, user_id):
        user_json = requests.get(random.choice(self.peers) + "/user/" + user_id)
        return user_json

    def request_transaction_data(self, tx_id):
        tx_json = requests.get(random.choice(self.peers) + "/transaction/" + tx_id)
        return tx_json

    def request_blockchain(self):
        blockchain_json = requests.get(random.choice(self.peers) + "/blockchain")
        self.blockchain = Blockchain.from_obj(json.loads(blockchain_json))

    def send_hello(self):
        # use broadcast
        async def broadcast():
            async with aiohttp.ClientSession() as session:
                tasks = []
                for peer in self.peers:
                    tasks.append(asyncio.ensure_future(session.get(peer + ':' + self.port + "/hello")))
            await asyncio.gather(*tasks)

        asyncio.run(broadcast())

    def send_transaction(self, transaction):
        # use broadcast
        data = transaction.to_json()

        async def broadcast():
            async with aiohttp.ClientSession() as session:
                tasks = []
                for peer in self.peers:
                    tasks.append(asyncio.ensure_future(session.post(peer + ':' + self.port + "/post/transaction", data=data)))
            await asyncio.gather(*tasks)

        asyncio.run(broadcast())
        
    def send_block(self, block):
        # use broadcast
        data = block.to_json()

        async def broadcast():
            async with aiohttp.ClientSession() as session:
                tasks = []
                for peer in self.peers:
                    tasks.append(asyncio.ensure_future(session.post(peer + ':' + self.port + "/post/block", data=data)))
            await asyncio.gather(*tasks)

        asyncio.run(broadcast())

    def accept_block(self, block):
        # add a block to the blockchain and cancel any mining on the current block
        # start a new block
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
        pass


app = FastAPI()
node = Node()
node.bootstrap()

@app.get("/hello")
def hello():
    """
    Add the requesting IP to this server's list of peers.
    """
    pass

@app.get("/peers")
def get_peers():
    pass

@app.get("/blockchain")
def get_blockchain():
    """
    Return a copy of the entire blockchain, according to this node.
    """
    return "<p>Hello, World!</p>"

@app.get("/block")
def get_current_block():
    pass

@app.post("/post/block")
def receive_block(data):
    pass

@app.post("/post/transaction")
def receive_transaction(data):
    pass

@app.get("/user/{user}")
def get_user(user: str):
    # get all transactions associated with a user, using their public key
    pass

@app.get("/transaction/{id}")
def get_transaction(id: str):
    # use transaction hash?
    pass