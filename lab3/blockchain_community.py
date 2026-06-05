from ipv8.community import Community
from ipv8.lazy_community import lazy_wrapper
import asyncio
from chain.blockchain import Blockchain
from chain.miner import Miner, MinerThread
from chain.transaction import Transaction

from payloads import (
    SubmitTransactionPayload,
    SubmitTransactionResponsePayload,
    GetChainHeightPayload,
    ChainHeightResponsePayload,
    GetBlockPayload,
    BlockResponsePayload,
    TransactionBroadcastPayload,
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

        self.blockchain = Blockchain()
        self.miner = Miner(self.blockchain)
        self.miner_thread = MinerThread(self.miner, MINE_BLOCK_PER_SECONDS)

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
    # Broadcast Functions
    # ----------------------------------------------------------------------

    def broadcast_to_teammates(self, payload) -> None:
        for teammate_peer in [self.darian_peer, self.jayran_peer]:
            if teammate_peer is None:
                continue

            self.ez_send(teammate_peer, payload)

    def broadcast_transaction(self, tx: Transaction) -> None:
        """
        Broadcast a transaction to teammates so the miner can include it.
        """
        payload = TransactionBroadcastPayload(
            sender_key=tx.sender_key,
            data=tx.data,
            timestamp=tx.timestamp,
            signature=tx.signature,
        )

        self.broadcast_to_teammates(payload)

        print(f"Broadcasted transaction: {tx.tx_hash().hex()}")

    # ---------------------------------------------------------------------
    # Payload Response Functions
    # ---------------------------------------------------------------------

    @lazy_wrapper(SubmitTransactionPayload)
    def on_submit_transaction(self, peer, payload):
        print("-- Incoming Transaction -- ")
        if not self.is_server_peer(peer):
            print("Ignoring SubmitTransactionPayload from non-server peer")
            return

        tx = Transaction(
            payload.sender_key, payload.data, payload.timestamp, payload.signature
        )

        if not tx.valid_signature():
            response = SubmitTransactionResponsePayload(
                False,
                tx.tx_hash(),
                "Rejected transaction: invalid signature",
            )
            self.ez_send(peer, response)
            return

        if not self.blockchain.mempool.add_transaction(tx):
            response = SubmitTransactionResponsePayload(
                False,
                tx.tx_hash(),
                "Transaction already exists in mempool",
            )
            self.ez_send(peer, response)
            return

        response = SubmitTransactionResponsePayload(
            True,
            tx.tx_hash(),
            "Transaction accepted",
        )
        self.ez_send(peer, response)

        self.broadcast_transaction(tx)
        print("Broadcasted submitted transaction to teammate peers\n")

    @lazy_wrapper(GetChainHeightPayload)
    def on_get_chain_height(self, peer, payload):
        if not self.is_server_peer(peer):
            print("Ignoring GetChainHeightPayload from non-server peer")
            return

        height = self.blockchain.height()
        tip_hash = self.blockchain.previous_hash()

        response = ChainHeightResponsePayload(payload.request_id, height, tip_hash)
        self.ez_send(peer, response)
        print(f"Sent chain height response, height={height}, tip={tip_hash.hex}")

    @lazy_wrapper(GetBlockPayload)
    def on_get_block(self, peer, payload):
        if not self.is_server_peer(peer):
            print("Ignoring response from non-server peer")
            return

        block = self.blockchain.get_block(payload.height)

    @lazy_wrapper(SubmitTransactionPayload)
    def on_submit_transaction(self, peer, payload: SubmitTransactionPayload):

        if not self.is_server_peer(peer):
            print("Ignoring SubmitTransaction from non-server peer")
            return

        tx = Transaction(
            sender_key=payload.sender_key,
            data=payload.data,
            timestamp=payload.timestamp,
            signature=payload.signature,
        )

        tx_hash = tx.tx_hash()

        if not verify_transaction_signature(tx):
            response = SubmitTransactionResponsePayload(
                success=False,
                tx_hash=tx_hash,
                message="Invalid transaction signature",
            )

            self.ez_send(peer, response)

            print(
                f"Rejected transaction: invalid signature, " f"tx_hash={tx_hash.hex()}"
            )
            return

        if self.blockchain.mempool.contains(tx_hash):
            response = SubmitTransactionResponsePayload(
                success=True,
                tx_hash=tx_hash,
                message="Transaction already in mempool",
            )

            self.ez_send(peer, response)

            print(f"Duplicate transaction already in mempool: {tx_hash.hex()}")
            return

        if tx_hash in self.blockchain.get_canonical_tx_hashes():
            response = SubmitTransactionResponsePayload(
                success=True,
                tx_hash=tx_hash,
                message="Transaction already included in best chain",
            )

            self.ez_send(peer, response)

            print(f"Transaction already in best chain: {tx_hash.hex()}")
            return

        self.blockchain.add_transaction(tx)

        response = SubmitTransactionResponsePayload(
            success=True,
            tx_hash=tx_hash,
            message="Transaction accepted into mempool",
        )

        self.ez_send(peer, response)

        print(f"Accepted transaction: {tx_hash.hex()}")
        print(f"Mempool size: {self.blockchain.mempool.size()}")

        # Share transaction with teammates.
        self.broadcast_transaction(tx)

        print("Broadcasted submitted transaction to teammates")

    @lazy_wrapper(GetChainHeightPayload)
    def on_get_chain_height(self, peer, payload: GetChainHeightPayload):

        if not self.is_server_peer(peer):
            print("Ignoring GetChainHeight from non-server peer")
            return

        height = self.blockchain.height()
        tip_hash = self.blockchain.tip_hash()

        response = ChainHeightResponsePayload(
            request_id=payload.request_id,
            height=height,
            tip_hash=tip_hash,
        )

        self.ez_send(peer, response)

        print(f"Sent chain height response: height={height}, tip={tip_hash.hex()}")

    @lazy_wrapper(GetBlockPayload)
    def on_get_block(self, peer, payload: GetBlockPayload):

        if not self.is_server_peer(peer):
            print("Ignoring GetBlock from non-server peer")
            return

        block = self.blockchain.get_block(payload.height)

        if block is None:
            print(f"Requested invalid block height: {payload.height}")
            return
        
        response = BlockResponsePayload(
            height=payload.height,
            prev_hash=block.header.prev_hash,
            txs_hash=block.header.txs_hash,
            timestamp=block.header.timestamp,
            difficulty=block.header.difficulty,
            nonce=block.header.nonce,
            block_hash=block.header.block_hash(),
            tx_hashes=b"".join(tx.tx_hash() for tx in block.transactions),
        )

        self.ez_send(peer, response)

        print(f"Sent block response for height={payload.height}")
        print(f"block_hash={block.header.block_hash()}")
        print(f"tx_count={len(block.transactions)}")

    # @lazy_wrapper(BlockPayload)
    # async def on_block(self, peer, payload):
    #     # block = deserialize(payload)
    #     block = payload.block

    #     if self.blockchain.append_block(block):

    #         # stop current mining immediately
    #         self.miner.stop_event.set()
