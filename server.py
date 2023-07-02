from fastapi import FastAPI, Request
from common import Transaction, Block, Blockchain, Node
import json
from threading import Thread

node = Node()

app = FastAPI()
@app.get("/hello")
def hello(request: Request):
    """
    Add the requesting IP to this server's list of peers.
    """
    if request.client.host not in node.peers:
        node.peers.append(request.client.host)
    return {"response": 1}

@app.get("/peers")
def get_peers():
    return json.dumps({"peers": node.peers})

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
async def receive_block(request: Request):
    data = await request.body()
    block_json = json.loads(data)
    block = Block.from_obj(block_json)
    node.handle_block(block)

from pydantic import BaseModel
from typing import List
class JSONTransactionInput(BaseModel):
    tx_id: str
    tx_output_index: int
    signature: str

class JSONTransactionOutput(BaseModel):
    amount: int
    recipient: str

class JSONTransaction(BaseModel):
    id: str
    inputs: List[JSONTransactionInput]
    outputs: List[JSONTransactionOutput]
    time: int

@app.post("/post/transaction")
async def receive_transaction(request: Request):
    #print(data)
    print("ba-bing")
    data = await request.body()
    tx_json = json.loads(data)
    tx = Transaction.from_obj(tx_json)
    node.handle_transaction(tx)

@app.get("/user/{user}")
def get_user(user: str):
    # get all confirmed transactions associated with a user, using their public key
    user_transactions = []
    for block in node.blockchain.blocks:
        for tx in block.transactions:
            outpoint = tx.get_user_outpoint(user)
            if outpoint is not None:
                print("found transaction")
                # This user either gained or lost money in this transaction
                print(outpoint["tx_id"])
                print(outpoint["tx_output_index"])
                outpoint["spent"] = node.blockchain.outpoint_lookup[bytes.fromhex(outpoint["tx_id"])][outpoint["tx_output_index"]].spent
                user_transactions.append(outpoint)
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
private_key_location = input()
if len(private_key_location) == 0:
    private_key_location = node.new_user("key.txt")
    print("A new user was created. The key has been saved to 'key.txt'.")
    input()
node.set_user(private_key_location)

mining_thread = Thread(target=node.start_core)
mining_thread.start()