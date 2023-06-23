from fastapi import FastAPI, Request
from common import Transaction, Block, Blockchain, Node
import json

node = Node()

app = FastAPI()
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

node.peers = []
node.bootstrap()

print("Enter the private key of the user to mine as.")
print("If nothing is entered, a new user will be created.")
private_key = input()
if len(private_key) == 0:
    private_key = node.new_user()
    print("A new user was created with the following private key:")
    print(private_key)
node.set_user(private_key)

node.start_core()