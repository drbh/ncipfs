import maya
import msgpack
import ipfsapi
import shutil
import os
import time
import datetime
import json

import base58
import base64

from timeit import default_timer as timer

from nucypher.characters.lawful import Enrico
from nucypher.characters.lawful import Bob, Ursula
from nucypher.config.characters import AliceConfiguration
from nucypher.crypto.powers import DecryptingPower, SigningPower
from nucypher.network.middleware import RestMiddleware
from nucypher.utilities.logging import SimpleObserver
from nucypher.crypto.kits import UmbralMessageKit
from nucypher.keystore.keypairs import DecryptingKeypair, SigningKeypair
from umbral.keys import UmbralPublicKey, UmbralPrivateKey




class ncipfs(object):
    """
    docstring for ncipfs
    """
    def __init__(self):
        self.name = "David"
        pass

    def connect(self, nucypher_network, ipfs_api_gateway): 
        """
        client = ncipfs.Connect(
            nucypher_network="localhost:11500",
            ipfs_api_gateway="localhost:5001"
        )
        """
        self.nucypher_network = nucypher_network
        self.ipfs_api_gateway = ipfs_api_gateway

        try:
            self.ipfs_gateway_api = ipfsapi.connect('127.0.0.1', 5001)
        except Exception as e: # should be more specific ConnectionRefusedError, NewConnectionError, MaxRetryError not sure
            print("Automatic Mode A Public Gateway will be used as a fallback")
            self.ipfs_gateway_api = ipfsapi.connect('https://ipfs.infura.io', 5001)


        # SEEDNODE_URL = self.nucypher_network
        POLICY_FILENAME = "policy-metadata.json"

        # # FOR LOCAL RUNNING NET
        # self.ursula = Ursula.from_seed_and_stake_info(
        #     seed_uri=SEEDNODE_URL,
        #     federated_only=True,
        #     minimum_stake=0
        # )

        self.ursula =urs = Ursula.from_teacher_uri(
            teacher_uri=self.nucypher_network,
            federated_only=True,
            min_stake=0
        )
        return True
    
    def create_new_user(self, name, password):
        passphrase = password
        direco = "accounts/"+ name
#         alice_config = AliceConfiguration(
#             config_root=os.path.join(direco),
#             is_me=True, known_nodes={self.ursula}, start_learning_now=True,
#             federated_only=True, learn_on_same_thread=True,
#         )
#         alice_config.initialize(password=passphrase)
#         alice_config.keyring.unlock(password=passphrase)
#         alice_config_file = alice_config.to_configuration_file()
        alice_config = AliceConfiguration(
            config_root=os.path.join(direco),
            is_me=True,
            known_nodes={self.ursula},
            start_learning_now=False,
            federated_only=True,
            learn_on_same_thread=True,
        )
        alice_config.initialize(password=passphrase)
        alice_config.keyring.unlock(password=passphrase)
        alice = alice_config.produce()
        alice_config_file = alice_config.to_configuration_file()
        alice.start_learning_loop(now=True)

        
        enc_privkey = UmbralPrivateKey.gen_key()
        sig_privkey = UmbralPrivateKey.gen_key()

        doctor_privkeys = {
            'enc': enc_privkey.to_bytes().hex(),
            'sig': sig_privkey.to_bytes().hex(),
        }

        DOCTOR_PUBLIC_JSON =  direco + '/recipent.public.json'
        DOCTOR_PRIVATE_JSON = direco + '/recipent.private.json'

        with open(DOCTOR_PRIVATE_JSON, 'w') as f:
            json.dump(doctor_privkeys, f)

        enc_pubkey = enc_privkey.get_pubkey()
        sig_pubkey = sig_privkey.get_pubkey()
        doctor_pubkeys = {
            'enc': enc_pubkey.to_bytes().hex(),
            'sig': sig_pubkey.to_bytes().hex()
        }
        with open(DOCTOR_PUBLIC_JSON, 'w') as f:
            json.dump(doctor_pubkeys, f)

        return alice

    def act_as_alice(self, name, password):
        dirname = "accounts/" + name + "/"
        congifloc = dirname + "alice.config"
        alice_config = AliceConfiguration(
            config_root=os.path.join(dirname),
            is_me=True, 
            known_nodes={self.ursula}, 
            start_learning_now=False,
            federated_only=True, 
            learn_on_same_thread=True,
        )
        
        cfg = alice_config.from_configuration_file(congifloc)
        cfg.keyring.unlock(password)
        alice = cfg.produce()
#         alice.start_learning_loop(now=True)
        return alice
    

    def act_as_bob(self, name):
        dirname = "accounts/" + name + "/"
        fname = dirname+"recipent.private.json"
        with open(fname) as data_file:    
            data = json.load(data_file)
        enc_privkey = UmbralPrivateKey.from_bytes(bytes.fromhex(data["enc"]))
        sig_privkey = UmbralPrivateKey.from_bytes(bytes.fromhex(data["sig"]))
        
        bob_enc_keypair = DecryptingKeypair(private_key=enc_privkey)
        bob_sig_keypair = SigningKeypair(private_key=sig_privkey)
        enc_power = DecryptingPower(keypair=bob_enc_keypair)
        sig_power = SigningPower(keypair=bob_sig_keypair)
        power_ups = [enc_power, sig_power]
        bob = Bob(
            is_me=True,
            federated_only=True,
            crypto_power_ups=power_ups,
            start_learning_now=True,
            abort_on_learning_error=True,
            known_nodes=[self.ursula],
            save_metadata=False,
            network_middleware=RestMiddleware(),
        )
        return bob

    def add_contents(self, alicia, my_label, contents): 
        """
        cid = client.add_contents(
            policy_pubkey=policy_pub_key
        )
        """
        policy_pubkey = alicia.get_policy_pubkey_from_label(my_label)

        data_source = Enrico(policy_encrypting_key=policy_pubkey)
        data_source_public_key = bytes(data_source.stamp)
        heart_rate = 80
        now = time.time()
        kits = list()
        heart_rate = contents
        now += 3
        heart_rate_data = { 'heart_rate': heart_rate, 'timestamp': now, }
        plaintext = msgpack.dumps(heart_rate_data, use_bin_type=True)
        message_kit, _signature = data_source.encrypt_message(plaintext)
        kit_bytes = message_kit.to_bytes()
        kits.append(kit_bytes)
        data = { 'data_source': data_source_public_key, 'kits': kits, }
#         print("🚀 ADDING TO IPFS D-STORAGE NETWORK 🚀")
        d = msgpack.dumps(data, use_bin_type=True)

        ### NETWORK ERROR OUT ON FALLBACK 
        cid = self.ipfs_gateway_api.add_bytes(d)
#         print("File Address:\t%s" % cid)
        return cid

    def add_data_and_grant_self_access(self, username, password, label, contents):
        alice = self.act_as_alice(username, password)
        cid = self.add_contents(alice, label.encode("utf-8"), contents)
        enc, sig = get_users_public_keys(username)
        nucid = creat_nucid(alice, cid, enc, sig, label.encode("utf-8"))
        return nucid

    def grant_others_access(self, username, password, cid, label, recp_enc_b58_key, recp_sig_b58_key):
        alice = self.act_as_alice(username, password)    
        enc = UmbralPublicKey.from_bytes(base58.b58decode(recp_enc_b58_key))
        sig = UmbralPublicKey.from_bytes(base58.b58decode(recp_sig_b58_key))
        nucid = creat_nucid(alice, cid, enc, sig, label.encode("utf-8"))
        return nucid


    def fetch_and_decrypt_nucid(self, username, nucid):
        item_cid, pol, sig, lab = ncipfs_to_policy(nucid)
        bob = self.act_as_bob(username)
        try:
            out = self.decrypt(bob, item_cid, pol, sig, lab)
        except:
            out = "Failed to decrypt"
        return out


    def decrypt(self, bob, item_cid, pol, sig, lab):
        policy_pubkey = UmbralPublicKey.from_bytes(bytes.fromhex(pol))
        alices_sig_pubkey = UmbralPublicKey.from_bytes(bytes.fromhex(sig))
        label = lab.encode()
        dat = self.ipfs_gateway_api.cat(item_cid)
        doctor = bob
        doctor.join_policy(label, alices_sig_pubkey)
        data = msgpack.loads(dat, raw=False)
        message_kits = (UmbralMessageKit.from_bytes(k) for k in data['kits'])
        data_source = Enrico.from_public_keys(
            {SigningPower: data['data_source']},
            policy_encrypting_key=policy_pubkey
        )
        message_kit = next(message_kits)
        start = timer()
        retrieved_plaintexts = doctor.retrieve(
            label=label,
            message_kit=message_kit,
            data_source=data_source,
            alice_verifying_key=alices_sig_pubkey
        )
        end = timer()
        plaintext = msgpack.loads(retrieved_plaintexts[0], raw=False)
        heart_rate = plaintext['heart_rate']
        timestamp = maya.MayaDT(plaintext['timestamp'])
        terminal_size = shutil.get_terminal_size().columns
        max_width = min(terminal_size, 120)
        columns = max_width - 12 - 27
        scale = columns / 40
        retrieval_time = "Retrieval time: {:8.2f} ms".format(1000 * (end - start))
        line = heart_rate# + "   " + retrieval_time
        return line


def creat_nucid(alice, cid, enc_pubkey, sig_pubkey, label):
    powers_and_material = { DecryptingPower: enc_pubkey, SigningPower: sig_pubkey }
    doctor_strange = Bob.from_public_keys(powers_and_material=powers_and_material, federated_only=True)
    policy_end_datetime = maya.now() + datetime.timedelta(days=5)
    # m, n = 1, 2
    m, n = 2, 3
    print(doctor_strange, label, m, n, policy_end_datetime)
    print(alice)
    policy = alice.grant(bob=doctor_strange, label=label, m=m, n=n, expiration=policy_end_datetime)
    policy_info = {
        "policy_pubkey": base58.b58encode(policy.public_key.to_bytes()).decode("utf-8"),
        "alice_sig_pubkey": base58.b58encode(bytes(alice.stamp)).decode("utf-8"),
        "label": label.decode("utf-8"),
    }
    
    store_url = "%s_%s_%s_%s"%(cid,
                               base58.b58encode(policy.public_key.to_bytes()).decode("utf-8"),
                               base58.b58encode(bytes(alice.stamp)).decode("utf-8"),
                               label.decode("utf-8"))

    store_url = "nucid://" + store_url

    return store_url


def get_users_public_keys(name, serialized=False):
    dirname = "accounts/" + name + "/"
    fname = dirname+"recipent.public.json"
    with open(fname) as data_file:    
        data = json.load(data_file)
    enc_pubkey = UmbralPublicKey.from_bytes(bytes.fromhex(data["enc"]))
    sig_pubkey = UmbralPublicKey.from_bytes(bytes.fromhex(data["sig"]))
    print(enc_pubkey, sig_pubkey)
    if serialized:
        return (base58.b58encode(bytes.fromhex(data["enc"])).decode("utf-8"),
         base58.b58encode(bytes.fromhex(data["sig"])).decode("utf-8"))
    return (enc_pubkey, sig_pubkey)



def ncipfs_to_policy(store_url):
    print(store_url)
    if len(store_url.split("//")[1].split("_")) == 2:
        return [
            elem 
            for idx, elem in enumerate(store_url.split("//")[1].split("_")) 
        ]        
    else:
        return [
            base58.b58decode(elem).hex()
            if idx != 0 and idx != 3 else elem 
            for idx, elem in enumerate(store_url.split("//")[1].split("_")) 
        ]
# n = ncipfs()

# n.connect("localhost:11501","localhost:5001")

# # n.create_new_user("person", "password password 123")

# my_nucid = add_data_and_grant_self_access("dholtz1", "12345678901234567890",
#                               "example.txt", "hello world")

# ## share with PERSON's keys

# shareable_nucid = grant_others_access("dholtz1", "12345678901234567890",
#                     "QmSWioSfDQA2tx8FNQEYPtXER7BTrFNwtuoAXUdCFp2gFi","example.txt",
#                     '24ig8sngFYbCu4eZQakU4RQhDdCJxccC28GV1E3m9d4E2',
#                     '28E9RhzxtZypGLMGgSAyxPy3Wdu1upaF7Bti6fynEz3iQ')


# fetch_and_decrypt_nucid("dholtz1", 'ncipfs://QmSWioSfDQA2tx8FNQEYPtXER7BTrFNwtuoAXUdCFp2gFi_pmkFc7WMN6KqUwK5U83sfMW5LBF1XbibsiQ2qR1XDWRg_gU7tg6RpWRAbtb57EuUErdj1npn1FiGF5wxfUeX3RuzZ_example.txt')


# fetch_and_decrypt_nucid("person", shareable_nucid)


# fetch_and_decrypt_nucid("philburt", shareable_nucid)

