import asyncio
import logging
import os
import time as time_module

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
from chain.blockchain import Blockchain
from chain.mempool import Mempool
from chain.miner import Miner
from chain.transaction import Transaction

import argparse
parser = argparse.ArgumentParser(description="Simple argparse example")
parser.add_argument("--register", action="store_true", help="Whether to register with the lab server (required for lab 3)")
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
        data=os.urandom(32),      # random payload
        timestamp=int(time_module.time()),
        signature=os.urandom(64), # fake signature for now
    )

async def main():
    ipv8 = init_ipv8()
    await ipv8.start()

    print("IPv8 started.")

    blockchain_community = ipv8.get_overlay(BlockchainCommunity)

    my_peer = blockchain_community.my_peer
    public_bytes = my_peer.public_key.key_to_bin()
    print(f"Connecting With Public Key: {public_bytes.hex()}")

    miner_node = Miner(blockchain_community.blockchain, blockchain_community.mempool)

    # make a thread , that every MINE_BLOCK_PER_SECONDS mines a block. And sends it to the others. 
    # await miner_node.mine_block() 

    while True:
        tx = create_dummy_transaction(public_bytes)
        blockchain_community.mempool.add_transaction(tx)
        print(f"Added tx {tx.tx_hash().hex()[:16]}...")

        block = await miner_node.mine_block()
        print(f"Mined a new block with hash: {block.header.block_hash().hex()}")
        blockchain_community.blockchain.print_chain()

        await asyncio.sleep(MINE_BLOCK_PER_SECONDS)

    try:
        await blockchain_community.find_teammates()

        if args.register:
            registration_community = ipv8.get_overlay(LabRegistrationCommunity)
            await registration_community.find_server()
            registration_community.register_blockchain()

        # await asyncio.sleep(0.1)
        await run_forever()

    except (KeyboardInterrupt, asyncio.CancelledError):
        print("Interrupted by user.\n")
    finally:
        await ipv8.stop()
        print("IPV8 Stopped.")


if __name__ == "__main__":
    asyncio.run(main())
