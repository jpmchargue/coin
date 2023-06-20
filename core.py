from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from fastapi import FastAPI, Request

import hashlib
import json
import requests
import math
import time
import random

import asyncio
import aiohttp
import uvicorn


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
    def __init__(self, tx_id, tx_output_index, op_recipient, op_value):
        self.previous_tx_id = tx_id
        self.previous_tx_output_index = tx_output_index
        self.previous_tx_output_recipient = op_recipient
        self.previous_tx_output_value = op_value
        self.spent = False

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

    def involves_user(self, public_key):
        for to in self.outputs:
            if to.recipient == public_key:
                return True
        return False


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

    def to_hash(self):
        return hash(self.to_json())

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
        
        #self.block_lookup = {}
        self.transaction_lookup = {}
        self.outpoint_lookup = {}

    def add_transaction(self, transaction):
        """
        Add a transaction to the current block.
        """
        # Add transactions to transaction lookup
        self.transaction_lookup[transaction.id] = transaction

        # Add outpoints to outpoint lookup
        outpoints = [Outpoint(transaction.id, i, to.recipient, to.amount) for i, to in enumerate(transaction.outputs)]
        self.outpoint_lookup[transaction.id] = outpoints

        # Record when outpoints are spent
        for ti in transaction.inputs:
            if ti.previous_tx_id in self.outpoint_lookup \
                    and ti.previous_tx_output_index < len(self.outpoint_lookup[ti.previous_tx_id]):
                self.outpoint_lookup[ti.previous_tx_id][ti.previous_tx_outpoint_index].spent = True

    def add_block(self, block):
        self.blocks.append(block)
        for tx in block.transactions:
            self.add_transaction(tx)

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
        for block_obj in obj["blocks"]:
            blockchain.add_block(Block.from_obj(block_obj))
        return blockchain


class Node():
    def __init__(self):
        self.peers = BOOTSTRAP_NODES
        self.port = SERVER_PORT
        self.blockchain = Blockchain()

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
                    tasks.append(asyncio.ensure_future(session.get("http://" + peer + ':' + self.port + "/hello")))
            await asyncio.gather(*tasks)

        asyncio.run(broadcast())

    def send_transaction(self, transaction):
        # use broadcast
        data = transaction.to_json()

        async def broadcast():
            async with aiohttp.ClientSession() as session:
                tasks = []
                for peer in self.peers:
                    tasks.append(asyncio.ensure_future(session.post("http://" + peer + ':' + self.port + "/post/transaction", data=data)))
            await asyncio.gather(*tasks)

        asyncio.run(broadcast())
        
    def send_block(self, block):
        # use broadcast
        data = block.to_json()

        async def broadcast():
            async with aiohttp.ClientSession() as session:
                tasks = []
                for peer in self.peers:
                    tasks.append(asyncio.ensure_future(session.post("http://" + peer + ':' + self.port + "/post/block", data=data)))
            await asyncio.gather(*tasks)

        asyncio.run(broadcast())

    def accept_block(self, block):
        # add a block to the blockchain and cancel any mining on the current block
        # start a new block
        pass

    def start_mining(self):
        pass

    def verify_transaction(self, transaction):
        # Transaction must not already exist
        if transaction.id in self.blockchain.transaction_lookup:
            return False
        outpoints = [self.blockchain.outpoint_lookup[ti.previous_tx_id][ti.previous_tx_output_index] for ti in transaction.inputs]
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
            if op.spent:
                return False

            total_input_value += op.previous_tx_output_value
        # Total transaction input value must equal output value
        total_output_value = sum([to.amount for to in transaction.outputs])
        if total_input_value != total_output_value:
            return False
        return True

    def verify_block(self, block):
        # Block index must be correct
        if len(self.blockchain.blocks) == 0 and block.index != 0:
            return False
        elif block.index != self.blockchain.blocks[-1] + 1:
            return False
        
        # Previous block hash must be correct
        if block.previous_hash != self.blockchain.blocks[-1].to_hash():
            return False

        def transaction_is_reward(transaction):
            if len(transaction.inputs) > 1:
                return False
            if transaction.inputs[0].signature != bytes(1):
                return False
            if len(transaction.outputs) > 1:
                return False
            if transaction.outputs[0].amount > 100:
                return False
            return True

        # Verify all transactions in block
        seen_mining_fee = False
        for tx in block.transactions:
            tx_is_valid = self.verify_transaction(tx)
            if not tx_is_valid:
                # A single 'invalid' transaction is allowed if this transaction is the mining reward
                if seen_mining_fee:
                    return False
                elif transaction_is_reward(tx):
                    seen_mining_fee = True
                else:
                    return False

        return True

    def handle_transaction(self, transaction):
        # check if a transaction is valid, and add it if so
        if self.verify_transaction(transaction):
            self.blockchain.add_transaction(transaction)

    def handle_block(self, block):
        # check if a block is valid, and add it if so
        if self.verify_block(block):
            self.blockchain.add_block(block)
            self.blockchain.current_block = Block()

    def start_core(self):
        print("Sending hello...")
        self.send_hello()

        print("Starting server...")
        uvicorn.run("core:app", port=SERVER_PORT, log_level="info")

        print("Beginning mining.")
        self.mine()

    def mine(self):
        # start a background thread running this function as a process.
        # run a loop where a nonce is created and tested, and if its hash
        # has a certain number of zeros, broadcast it.
        while True:
            candidate_nonce = random.randbytes(8)
            difficulty = 2

            # Create a copy of the current block to avoid a race condition
            candidate_block = Block.from_copy(self.blockchain.current_block)
            candidate_block.time = math.floor(time.time())
            hash_string = candidate_block.check_nonce(candidate_nonce).hex()
            if hash_string.ends_with("0" * difficulty):
                # You mined the block!
                candidate_block.nonce = candidate_nonce
                self.send_block(candidate_block)
                self.blockchain.add_block(candidate_block)
                self.blockchain.current_block = Block(
                        self.blockchain.blocks[-1].index + 1,
                        self.blockchain.blocks[-1].to_hash()
                )


app = FastAPI()
node = Node()
node.bootstrap()
node.start_core()

@app.get("/hello")
def hello(request: Request):
    """
    Add the requesting IP to this server's list of peers.
    """
    node.peers.append(request.client.host)
    return {"response": 1}

@app.get("/peers")
def get_peers():
    return json.dumps(node.peers)

@app.get("/blockchain")
def get_blockchain():
    """
    Return a copy of the entire blockchain, according to this node.
    """
    return node.blockchain.to_json()

@app.get("/block")
def get_current_block():
    return node.blockchain.current_block.to_json()

@app.post("/post/block")
def receive_block(data):
    block_json = json.loads(data)
    block = Block.from_obj(block_json)
    node.handle_block(Blockchain.from_obj(block))

@app.post("/post/transaction")
def receive_transaction(data):
    tx_json = json.loads(data)
    tx = Transaction.from_obj(tx_json)
    node.handle_transaction(tx)

@app.get("/user/{user}")
def get_user(user: str):
    # get all confirmed transactions associated with a user, using their public key
    user_transactions = []
    for block in node.blockchain.blocks:
        for tx in block.transactions:
            if tx.involves_user(user):
                user_transactions.append(tx.to_obj())
    return json.dumps(user_transactions)

@app.get("/transaction/{hex}")
def get_transaction(hex: str):
    # use transaction hash?
    tx_id = bytes.fromhex(hex)
    tx = node.blockchain.transaction_lookup[tx_id]
    return tx.to_json()