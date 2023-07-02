from common import Node


node = Node()
node.bootstrap()

title = "----- ShitCoin Lite -----"
greeting = """*--------------------------------*
| commands
| newuser - create a new user
| setuser {key file name} - log in a user
| whoami - show information about the current user
| getpeers - update the list of peer nodes
| showpeers - show the current list of peer nodes
| getuser {public key hexadecimal} - get information on all transactions involving a user
| gettx {transaction ID} - get information on a transaction
| getchain - get the entire blockchain
|
| send {previous transaction ID} {output index} {public key hexadecimal} {amount} -
|    send a certain amount of coin to the user with the given public key, and draw
|    the coins from the output from the given transaction/output index.
|
| help - show this again
| exit - quit ShitCoin lite
*---------------------------------*"""

print(title)
print(greeting)
while True:
    command = input()

    command_split = command.split(' ')
    if command_split[0] == "getpeers":
        node.update_peers()
    elif command_split[0] == "showpeers":
        print(node.peers)
    elif command_split[0] == "newuser":
        private_key_location = node.new_user("lite.txt")
        print(f"Created new user with key saved at {private_key_location}")
    elif command_split[0] == "setuser":
        try:
            node.set_user(command_split[1])
            print("Successfully set user")
        except ValueError:
            print(f"{command_split[1]} is not a valid key file")
        except FileNotFoundError:
            print(f"{command_split[1]} does not exist")
    elif command_split[0] == "whoami":
        if node.keys is None:
            print("n/a - no user logged in")
        else:
            print(f"Public Key: {node.keys.public_key()}")
            print(f"Public Key Hexadecimal: {node.keys.public_key().hex()}")
            print(f"Private key was loaded from {node.key_path}")
    elif command_split[0] == "send":
        previous_tx_id = command_split[1]
        previous_tx_output_index = int(command_split[2])
        recipient = command_split[3]
        amount = int(command_split[4])
        transaction = node.create_transaction(
                previous_tx_id,
                previous_tx_output_index,
                recipient,
                amount
        )
        if transaction is not None:
            print("Transaction JSON:")
            print(transaction.to_json())
            node.send_transaction(transaction)
    elif command_split[0] == "gettx":
        response = node.request_transaction_data(command_split[1])
        print(response)
    elif command_split[0] == "getuser":
        public_key = node.keys.public_key().hex() if len(command_split) <= 1 else command_split[1]
        response = node.request_user_data(public_key)

        balance = 0
        unspent_transactions = []
        for outpoint in response:
            if not outpoint["spent"]:
                unspent_transactions.append(outpoint)
                balance += outpoint["amount"]

        print('\n')
        print(f"STATISTICS FOR USER {public_key[:10]}...")
        print(f"Balance: {balance}")
        print("UNSPENT TRANSACTIONS:")
        for tx in unspent_transactions:
            tx_id = tx["tx_id"]
            tx_output_index = tx["tx_output_index"]
            tx_amount = tx["amount"]
            print(f"ID: {tx_id}")
            print(f"  Index: {tx_output_index}")
            print(f"  Amount: {tx_amount}")
        
    elif command_split[0] == "getchain":
        response = node.request_blockchain()
        print(response)

    elif command_split[0] == "help":
        print(greeting)
    elif command_split[0] == "exit":
        break

    print("-------------------------")
