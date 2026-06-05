import asyncio
import logging
import os
import time as time_module
import threading

from ipv8.community import *
from ipv8.configuration import (
    ConfigBuilder,
    Strategy,
    WalkerDefinition,
    default_bootstrap_defs,
)
from ipv8.util import run_forever
from ipv8_service import IPv8
from config import *
from registration.registration_community import LabRegistrationCommunity
from blockchain_community import BlockchainCommunity
from chain.miner import Miner, MinerThread
from chain.transaction import Transaction

import argparse

parser = argparse.ArgumentParser(description="Client for Lab 3: Blockchain")
parser.add_argument(
    "--register",
    action="store_true",
    help="Whether to register with the lab server (required for lab 3)",
)
parser.add_argument(
    "--test",
    action="store_true",
    help="Makes local blocks with fake transactions, and mines them. Useful for testing the mining and block validation logic without needing to connect to other peers.",
)
args = parser.parse_args()


def init_ipv8():
    builder = ConfigBuilder().clear_keys().clear_overlays()

    builder.add_key("mynode", "curve25519", "key.pem")

    # Add the Lab Registration Community: Only used for registering with lab 3 server
    builder.add_overlay(
        "LabRegistrationCommunity",
        "mynode",
        [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        [],
    )

    # Add our own Blockchain Community
    builder.add_overlay(
        "BlockchainCommunity",
        "mynode",
        [WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})],
        default_bootstrap_defs,
        {},
        [],
    )

    ipv8 = IPv8(
        builder.finalize(),
        extra_communities={
            "LabRegistrationCommunity": LabRegistrationCommunity,
            "BlockchainCommunity": BlockchainCommunity,
        },
    )
    logging.getLogger("LabRegistrationCommunity").setLevel(logging.CRITICAL)
    logging.getLogger("BlockchainCommunity").setLevel(logging.CRITICAL)

    return ipv8


def create_dummy_transaction(public_key: bytes) -> Transaction:
    return Transaction(
        sender_key=public_key,
        data=os.urandom(32),  # random payload
        timestamp=int(time_module.time()),
        signature=os.urandom(64),  # fake signature for now
    )


async def test_mining(blockchain_community: BlockchainCommunity):
    start_height = blockchain_community.blockchain.height()

    print(f"Starting test at height {start_height}")

    for i in range(3):
        tx1 = create_dummy_transaction(
            blockchain_community.my_peer.public_key.key_to_bin()
        )
        tx2 = create_dummy_transaction(
            blockchain_community.my_peer.public_key.key_to_bin()
        )

        blockchain_community.blockchain.mempool.add_transaction(tx1)
        blockchain_community.blockchain.mempool.add_transaction(tx2)

        print(f"[{i}] Added tx {tx1.tx_hash().hex()[:16]}...")
        print(f"[{i}] Added tx {tx2.tx_hash().hex()[:16]}...")

        while blockchain_community.blockchain.height() == start_height + i:
            await asyncio.sleep(0.5)

        new_height = blockchain_community.blockchain.height()
        print(f"New block mined! Height = {new_height}")

        blockchain_community.blockchain.print_chain()


async def main():
    ipv8 = init_ipv8()
    await ipv8.start()

    print("IPv8 started.")

    blockchain_community = ipv8.get_overlay(BlockchainCommunity)

    my_peer = blockchain_community.my_peer
    public_bytes = my_peer.public_key.key_to_bin()
    print(f"Connecting With Public Key: {public_bytes.hex()}")

    try:
        # Thread our miner keeps running and mines blocks every MINE_BLOCK_PER_SECONDS seconds, if a new block comes in it stops mining and that block is added to the blockchain. THen it will wait again 15 seconds and start mining again.
        thread = threading.Thread(
            target=blockchain_community.miner_thread.run, daemon=True
        )

        if args.test:
            thread.start()
            await test_mining(blockchain_community)

        await blockchain_community.find_teammates()

        if args.register:
            registration_community = ipv8.get_overlay(LabRegistrationCommunity)
            await registration_community.find_server()
            registration_community.register_blockchain()

        if not args.test:
            thread.start()

        # await asyncio.sleep(0.1)
        await run_forever()

    except (KeyboardInterrupt, asyncio.CancelledError):
        print("Interrupted by user.\n")
    finally:
        await ipv8.stop()
        print("IPV8 Stopped.")


if __name__ == "__main__":
    asyncio.run(main())
