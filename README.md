# coin 💰
A bare-bones implementation of a cryptocurrency in Python.

This repository is missing some quality-of-life features that are present in industry-standard cryptocurrencies (such as wallets that combine multiple keys, username/password pairs instead of public-private key pairs, etc.) But, this implementation does capture all of the necessary functionality to maintain a secure blockchain, per the [Bitcoin whitepaper](https://bitcoin.org/bitcoin.pdf). **This repository was made as a fun side project to figure out how to implement every part of a cryptocurrency in Python, and was not intended to be an optimal implementation.**

FastAPI is used to manage incoming connections, and AIOHttp is used for sending outgoing requests in most situations (anywhere where Requests would be too slow).

## Quickstart
Install the necessary dependencies using *pip*:
```
pip install -r requirements.txt
```

Run an instance of the core program (i.e. the 'miner') using core.py. For the instance to work properly (a.k.a. to receive transactions), you will have to port forward on port 5000 for your machine.
```
python core.py
```

Run an instance of the lite program using lite.py. This script allows you to send coins to other users and view information about the blockchain.
```
python lite.py
```