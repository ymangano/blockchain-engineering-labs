from chain.block import BlockHeader, Block, compute_txs_hash
from chain.transaction import Transaction
from config import BLOCK_DIFFICULTY, HASH_SIZE

def mine_block(
    prev_hash: bytes,
    transactions: list[Transaction],
    timestamp: int,
    difficulty: int = BLOCK_DIFFICULTY,
) -> Block:
    """
    Mine a new block.

    Mining means:
    - choose the transactions for the block
    - compute txs_hash
    - build a block header pointing to prev_hash
    - try nonce values until the block hash satisfies the difficulty

    This function returns a full valid Block.
    """
    assert len(prev_hash) == HASH_SIZE

    tx_hashes = [tx.tx_hash() for tx in transactions]
    txs_hash = compute_txs_hash(tx_hashes)

    nonce = 0

    header = BlockHeader(
        prev_hash=prev_hash,
        txs_hash=txs_hash,
        timestamp=timestamp,
        difficulty=difficulty,
        nonce=nonce,
    )

    while True:
        header.nonce = nonce

        block = Block(
            header=header,
            transactions=transactions,
        )

        if block.validate():
            return block

        nonce += 1
