from ipv8.community import Community
from ipv8.lazy_community import lazy_wrapper
import asyncio

from payloads import (
    SubmitTransactionPayload,
    SubmitTransactionResponsePayload,
    GetChainHeightPayload,
    ChainHeightResponsePayload,
    GetBlockPayload,
    BlockResponsePayload,
)

from config import *


class BlockchainCommunity(Community):
    community_id = bytes.fromhex(BLOCKCHAIN_COMMUNITY_ID)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.add_message_handler(SubmitTransactionPayload, self.on_submit_transaction)
        self.add_message_handler(GetChainHeightPayload, self.on_get_chain_height)
        self.add_message_handler(GetBlockPayload, self.on_get_block)

        self.darian_peer = None
        self.jayran_peer = None

        self.group_id = "d8c9d397bea2ee37"

    async def find_teammates(self):
        print("Looking for teammates...\n")
        found_jayran, found_darian = False, False

        while not (found_jayran and found_darian):
            peers = self.get_peers()
            print(f"Discovered {len(peers)} peer(s)")

            for peer in peers:
                peer_key = peer.public_key.key_to_bin().hex()

                if peer_key == MEMBER_1_PUBLIC_KEY_HEX:
                    print("Found Darian's node!")
                    self.darian_peer = peer
                    found_darian = True

                elif peer_key == MEMBER_2_PUBLIC_KEY_HEX:
                    print("Found Jayran's node!")
                    self.jayran_peer = peer
                    found_jayran = True

                else:
                    print("Other peer found, skipping ..")

            await asyncio.sleep(1)

        print("Found all required peers!")

    def is_server_peer(self, peer):
        return peer.public_key.key_to_bin().hex() == SERVER_PUBLIC_KEY_HEX

    # ---------------------------------------------------------------------
    # Payload Response Functions
    # ---------------------------------------------------------------------

    @lazy_wrapper(SubmitTransactionPayload)
    def on_submit_transaction(self, peer, payload):

        if not self.is_server_peer(peer):
            print("Ignoring response from non-server peer")
            return

        print("SERVER RESPONSE:")
        print(payload)

    @lazy_wrapper(GetChainHeightPayload)
    def on_get_chain_height(self, peer, payload):

        if not self.is_server_peer(peer):
            print("Ignoring response from non-server peer")
            return

        print("SERVER RESPONSE:")
        print(payload)

    @lazy_wrapper(GetBlockPayload)
    def on_get_block(self, peer, payload):

        if not self.is_server_peer(peer):
            print("Ignoring response from non-server peer")
            return

        print("SERVER RESPONSE:")
        print(payload)
