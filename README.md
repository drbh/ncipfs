# NCIPFS

[![Python 3.6](https://img.shields.io/badge/python-3.7-blue.svg)](https://www.python.org/downloads/release/python-370/) [![License](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/licenses/MIT)

## Welcome to NCIPFS

This project makes it easy to secure data on IPFS with NuCyphers awesome proxy re encryption. This libaray is under development and are finializing the API.

### Example Scenario:  

`David` wants to upload a 1 TB file and allow `Kathy` and `Joe` access. 

Traditionally he would ask `Kathy` and `Joe` for their respecive public keys and then he would encrypt the data twice; once for each key. Then store the encrypted value somewhere they could retrived it. He'll use IPFS as this datastore. 

However NuCyphers proxy re-encryption allows us to encrypt the data once, then re-encrypt new keys that will allow the two parties access. In this system we only encrypt the 1 TB once, and only store 1 TB on IPFS, this saves us storage space, encryption time, and ecryption computations. 

### Benefits

✅ **Y**ou **O**nly **E**ncrypt **O**nce **(Y.O.E.O kinda like Y.O.L.O)**  
✅ Verified (immutable data store)  
✅ Only re-encrypt keys for viewers  
✅ Distributed - no single point of failure  
✅ Can run federated (centralized) or distributed (ECR20 token incentivized)  

### Use cases

💡 Distributing large datasets  
💡 Distributing data to many people  
💡 IOT datastored (check out the original hearbeat example)  

### Implementations

🐥 Python 3 (stable IPFS and NuCypher codebases)  
🥚 Node JS (waiting on stable NyCypher codebase)  
🥚 Golang (waiting on stable NyCypher codebase) 


## Installation

### Library

```
pip install ncipfs
```

### Development

```python
git clone https://github.com/drbh/ncipfs.git
cd ncipfs.git
```

We use `pipenv` to manage any of the deps
```
# install deps and access virtual env
pipenv install
pipenv shell
```

## Implementation

On the top level there is a class named **NCIPFS**. This class handles the connection to an **IPFS Gateway** a **NuCypher Network** and access to **Local File Store** that handles all of the users keys. 


Top level diagram -- 

## API

### NCIPFS Methods 

connect(self, nucypher_network, ipfs_api_gateway)

create_new_user(self, name, password)

act_as_alice(self, name, password)

act_as_bob(self, name)

add_contents(self, alicia, my_label, contents):

add_data_and_grant_self_access(self, username, password, label, contents)

grant_others_access(self, username, password, cid, label, recp_enc_b58_key, recp_sig_b58_key)

fetch_and_decrypt_nucid(self, username, nucid)

decrypt(self, bob, item_cid, pol, sig, lab)

### Top Level Functions

creat_nucid(alice, cid, enc_pubkey, sig_pubkey, label)

get_users_public_keys(name, serialized=False)

ncipfs_to_policy(store_url)

