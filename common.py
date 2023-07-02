from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

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
    #"208.59.107.225"
    "127.0.0.1"
]
SERVER_PORT = 5000
MINING_REWARD = 100

def hash(data):
    #data = bytes(string, 'utf-8')
    hash_algorithm = hashlib.sha256()
    hash_algorithm.update(data)
    return hash_algorithm.digest()

class Keys():
    pem_header = b"-----BEGIN PUBLIC KEY-----\n"
    pem_footer = b"\n-----END PUBLIC KEY-----\n"
    def __init__(self, private_key):
        self.private_key = private_key
    def generate_new_pair():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,
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
    def make_readable_key(self, save_as):
        key = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(save_as, 'wb') as file:
            file.write(key)
    def from_readable_key(readable_key):
        with open(readable_key, 'rb') as file:
            private_key = serialization.load_pem_private_key(
                file.read(),
                password=None,
            )
            return Keys(private_key)
    def public_key(self):
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )[27:-26]
    def verify_signature(string, signature, public_key):
        key_data = Keys.pem_header + public_key + Keys.pem_footer
        public_key_obj = serialization.load_pem_public_key(key_data)
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
        self.previous_tx_id = previous_tx_id # bytes
        self.previous_tx_output_index = previous_tx_output_index # int
        self.signature = signature # bytes

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
        #print("signing " + str(previous_tx_id.hex()) + str(previous_tx_output_index))
        signature = keys.sign(str(previous_tx_id.hex()) + str(previous_tx_output_index))
        #print(signature)
        #print(Keys.verify_signature(str(previous_tx_id.hex()) + str(previous_tx_output_index), signature, keys.public_key()))
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
            "tx_id": ti.previous_tx_id.hex(),
            "tx_output_index": ti.previous_tx_output_index,
            "signature": ti.signature.hex()
        } for ti in self.inputs]
        obj_outputs = [{
            "amount": to.amount,
            "recipient": to.recipient.hex()
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
        inputs = [TxIn(bytes.fromhex(ti["tx_id"]), ti["tx_output_index"], bytes.fromhex(ti["signature"])) for ti in obj["inputs"]]
        outputs = [TxOut(to["amount"], bytes.fromhex(to["recipient"])) for to in obj["outputs"]]
        transaction = Transaction(inputs, outputs)
        transaction.id = bytes.fromhex(obj["id"])
        transaction.time = obj["time"]
        return transaction

    def get_user_outpoint(self, public_key):
        for index, to in enumerate(self.outputs):
            if to.recipient.hex() == public_key:
                return {
                    "tx_id": self.id.hex(),
                    "tx_output_index": index,
                    "amount": to.amount
                }
        return None


class Block():
    def __init__(self, index, previous_hash, nonce=bytes(1), transactions=[], time=0):
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
            obj["index"], 
            bytes.fromhex(obj["previous_hash"]),
            bytes.fromhex(obj["nonce"]),
            transactions,
            obj["time"]
        )
        return block

    def to_hash(self, check_nonce=None):
        data = self.index.to_bytes(4, 'big') + self.previous_hash
        data += self.nonce if check_nonce is None else check_nonce
        for tx in self.transactions:
            data += tx.to_bytes()
        data += self.time.to_bytes(8, 'big')

        return hash(data)

    def add_transaction(self, transaction):
        self.transactions.append(transaction)


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
                self.outpoint_lookup[ti.previous_tx_id][ti.previous_tx_output_index].spent = True

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
        self.keys = None
        self.key_path = ""

    def bootstrap(self):
        # populate list of peers
        if len(self.peers) > 0:
            print("it has peers!")
            url = "http://" + random.choice(self.peers) + ":" + str(self.port) + "/peers"
            print(f"Fetching from {url}")
            peers_obj = json.loads(requests.get(url).json())
            for peer in peers_obj["peers"]:
                if peer not in self.peers:
                    self.peers.append(peer)

    def update_peers(self):
        if len(self.peers) > 0:
            url = "http://" + random.choice(self.peers) + ":" + str(self.port) + "/peers"
            print(f"Fetching from {url}")
            peers_json = requests.get(url).json()
            peers_obj = json.loads(peers_json)
            for peer in peers_obj["peers"]:
                if peer not in self.peers:
                    self.peers.append(peer)

    def request_user_data(self, user_id):
        if len(self.peers) > 0:
            url = "http://" + random.choice(self.peers) + ":" + str(self.port) + "/user/" + user_id
            print(f"Fetching from {url}")
            user_json = requests.get(url).json()
            return json.loads(user_json)

    def request_transaction_data(self, tx_id):
        if len(self.peers) > 0:
            url = "http://" + random.choice(self.peers) + ":" + str(self.port) + "/transaction/" + tx_id
            print(f"Fetching from {url}")
            tx_json = requests.get(url).json()
            return tx_json

    def request_blockchain(self):
        if len(self.peers) > 0:
            url = "http://" + random.choice(self.peers) + ":" + str(self.port) + "/blockchain"
            print(f"Fetching from {url}")
            blockchain_json = requests.get(url).json()
            self.blockchain = Blockchain.from_obj(json.loads(blockchain_json))
            return blockchain_json

    def new_user(self, save_as):
        self.keys = Keys.generate_new_pair()
        self.keys.make_readable_key(save_as)
        self.key_path = save_as
        return save_as

    def set_user(self, private_key):
        self.keys = Keys.from_readable_key(private_key)
        self.key_path = private_key

    def create_transaction(self, tx, tx_output_index, recipient, amount):
        print("Checking login...")
        if self.keys is None:
            print("transaction failed: no user is logged in to send from")
            return None 
        
        print("Fetching outpoint data...")
        transaction = json.loads(self.request_transaction_data(tx))
        outpoint = transaction["outputs"][tx_output_index]

        print("Validating user...")
        if outpoint["recipient"] != self.keys.public_key().hex():
            print("send failed: outpoint doesn't belong to the current user")

        transaction = Transaction.create(self.keys, bytes.fromhex(tx), tx_output_index, outpoint["amount"], bytes.fromhex(recipient), amount)
        return transaction

    def send_hello(self):
        # use broadcast
        async def broadcast():
            async with aiohttp.ClientSession() as session:
                tasks = []
                for peer in self.peers:
                    tasks.append(asyncio.ensure_future(session.get("http://" + peer + ':' + str(self.port) + "/hello")))
                await asyncio.gather(*tasks)

        asyncio.run(broadcast())

    def send_transaction(self, transaction):
        # use broadcast
        data = transaction.to_json()

        async def broadcast():
            async with aiohttp.ClientSession() as session:
                tasks = []
                for peer in self.peers:
                    url = "http://" + peer + ':' + str(self.port) + "/post/transaction"
                    print(f"sending to {url}")
                    #session.post(url)
                    tasks.append(asyncio.ensure_future(session.post(url, data=data)))
                    #print("sending")
                await asyncio.gather(*tasks)

        asyncio.run(broadcast())
        
    def send_block(self, block):
        # use broadcast
        data = block.to_json()

        async def broadcast():
            async with aiohttp.ClientSession() as session:
                tasks = []
                for peer in self.peers:
                    url = "http://" + peer + ':' + str(self.port) + "/post/block"
                    tasks.append(asyncio.ensure_future(session.post(url, data=data)))
                await asyncio.gather(*tasks)

        asyncio.run(broadcast())

    def verify_transaction(self, transaction):
        # Transaction must not already exist
        if transaction.id in self.blockchain.transaction_lookup:
            print("transaction ID already exists")
            return False
        outpoints = [self.blockchain.outpoint_lookup[ti.previous_tx_id][ti.previous_tx_output_index] for ti in transaction.inputs]
        total_input_value = 0
        for i in range(len(transaction.inputs)):
            ti = transaction.inputs[i]
            op = outpoints[i]
            # Transaction input signatures must be valid
            print("Checking " + ti.previous_tx_id.hex() + str(ti.previous_tx_output_index))
            input_is_valid = Keys.verify_signature(
                ti.previous_tx_id.hex() + str(ti.previous_tx_output_index),
                ti.signature,
                op.previous_tx_output_recipient
            )
            if not input_is_valid:
                print("signature not accepted")
                return False   
            # Transaction inputs cannot be double spent
            if op.spent:
                print("transaction was already spent")
                return False

            total_input_value += op.previous_tx_output_value
        # Total transaction input value must equal output value
        total_output_value = sum([to.amount for to in transaction.outputs])
        if total_input_value != total_output_value:
            print("input value must equal output value")
            return False
        
        print("transaction accepted")
        return True

    def verify_block(self, block):
        # Block index must be correct
        if len(self.blockchain.blocks) == 0 and block.index != 0:
            print("block index is incorrect")
            return False
        elif block.index != self.blockchain.blocks[-1].index + 1:
            print("block index is incorrect")
            return False
        
        # Previous block hash must be correct
        if block.previous_hash != self.blockchain.blocks[-1].to_hash():
            print("previous block hash is incorrect")
            return False

        def transaction_is_reward(transaction):
            if len(transaction.inputs) > 1:
                return False
            if transaction.inputs[0].signature != bytes(1):
                return False
            if len(transaction.outputs) > 1:
                return False
            if transaction.outputs[0].amount > MINING_REWARD:
                return False
            return True

        # Verify all transactions in block
        seen_mining_fee = False
        for tx in block.transactions:
            tx_is_valid = self.verify_transaction(tx)
            if not tx_is_valid:
                # A single 'invalid' transaction is allowed if this transaction is the mining reward
                if seen_mining_fee:
                    print("block rejected due to invalid transaction")
                    return False
                elif transaction_is_reward(tx):
                    seen_mining_fee = True
                else:
                    print("block rejected due to invalid transaction")
                    return False

        return True

    def handle_transaction(self, transaction):
        # check if a transaction is valid, and add it if so
        if self.verify_transaction(transaction):
            self.blockchain.current_block.add_transaction(transaction)

    def handle_block(self, block):
        # check if a block is valid, and add it if so
        if self.verify_block(block):
            self.blockchain.add_block(block)
            self.blockchain.current_block = self.initialize_block()

    def initialize_block(self):
        block_index = len(self.blockchain.blocks)
        block_hash = self.blockchain.blocks[-1].to_hash() if block_index > 0 else bytes(32)
        mining_reward = Transaction.create(self.keys, bytes(64), 0, MINING_REWARD, self.keys.public_key(), MINING_REWARD)
        block = Block(block_index, block_hash, transactions=[])
        block.transactions.append(mining_reward)
        return block

    def start_core(self):
        print("Requesting blockchain...")
        self.request_blockchain()

        print("Got blockchain:")
        print(self.blockchain.to_json())

        print("Sending hello...")
        self.send_hello()

        print("Initializing block...")
        self.blockchain.current_block = self.initialize_block()

        print("Mining...")
        self.mine()

    def mine(self):
        # start a background thread running this function as a process.
        # run a loop where a nonce is created and tested, and if its hash
        # has a certain number of zeros, broadcast it.
        while True:
            candidate_nonce = random.randbytes(8)
            difficulty = 5

            # Create a copy of the current block to avoid a race condition
            candidate_block = Block.from_copy(self.blockchain.current_block)
            candidate_block.time = math.floor(time.time())
            hash_string = candidate_block.to_hash(check_nonce=candidate_nonce).hex()

            #print(f"Got hash {hash_string}")

            if hash_string.endswith("0" * difficulty):
                # You mined the block!
                print("BLOCK MINED!")

                candidate_block.nonce = candidate_nonce
                print(candidate_block.to_json())
                print(f"New Block Hash: {hash_string}")

                self.blockchain.add_block(candidate_block)

                self.send_block(candidate_block)
                new_block = self.initialize_block()
                self.blockchain.current_block = new_block

                print("Saved block, returning to mining...")