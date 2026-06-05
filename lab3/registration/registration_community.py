from ipv8.community import Community
from ipv8.lazy_community import lazy_wrapper
import asyncio

from .registration_payloads import RegisterBlockchainPayload, RegisterResponsePayload

from config import (
    BLOCKCHAIN_COMMUNITY_ID,
    LAB_COMMUNITY_ID,
    GROUP_ID,
    SERVER_PUBLIC_KEY_HEX,
)


class LabRegistrationCommunity(Community):
    community_id = LAB_COMMUNITY_ID

    def started(self):
        print("Lab registration community started!")
        print("Looking for peers...")

    def __init__(self, settings):
        super().__init__(settings)
        self.add_message_handler(RegisterResponsePayload, self.on_register_response)

        self.server_peer = None
        self.blockchain_community_id = bytes.fromhex(BLOCKCHAIN_COMMUNITY_ID)
        self.group_id = GROUP_ID

    @lazy_wrapper(RegisterResponsePayload)
    def on_register_response(self, peer, payload):
        if peer != self.server_peer:
            print("Ignoring response from non-server peer")
            return

        print("SERVER RESPONSE:")
        print(payload)

    async def find_server(self):
        print("Looking for server peer...")
        while self.server_peer is None:
            peers = self.get_peers()
            print(f"Discovered {len(peers)} peer(s)")

            for peer in peers:
                peer_key = peer.public_key.key_to_bin().hex()

                if peer_key == SERVER_PUBLIC_KEY_HEX:
                    print("FOUND THE SERVER!")
                    self.server_peer = peer
                    return

            await asyncio.sleep(1)

    def register_blockchain(self):
        payload = RegisterBlockchainPayload(
            group_id=self.group_id, community_id=self.blockchain_community_id
        )
        self.ez_send(self.server_peer, payload)

        print(
            "Sent blockchain registration request to server with group ID:",
            self.group_id,
        )
