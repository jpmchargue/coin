from common import Node


node = Node()
node.bootstrap()

while True:
    print("----- ShitCoin Lite -----")
    command = input()

    command_split = command.split(' ')
    if command_split[0] == "getpeers":
        node.update_peers()
    elif command_split[0] == "newuser":
        private_key = node.new_user()
        print("Created new user with key:")
        print(private_key)
    elif command_split[0] == "setuser":
        node.set_user(command_split[1])
        print("Successfully set user")
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
        print("Transaction JSON:")
        print(transaction.to_json())
        node.send_transaction(transaction)
    elif command_split[0] == "gettx":
        node.request_transaction_data(command_split[1])
    elif command_split[0] == "getuser":
        node.request_user_data(command_split[1])

