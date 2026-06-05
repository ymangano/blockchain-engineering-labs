from chain.transaction import Transaction


class Mempool:
    """
    Mempool stores transactions not yet included in a block.
        Key: tx_hash
        Value: Transaction
    """

    def __init__(self):
        self.transactions: dict[bytes, Transaction] = {}

    def add_transaction(self, tx: Transaction):
        """
        Add transaction to mempool.
        Returns the transaction hash.
        """
        tx_hash = tx.tx_hash()

        if tx_hash in self.transactions:
            print("Transaction already in mempool")
            return

        self.transactions[tx_hash] = tx

    def remove_transaction(self, tx_hash: bytes):
        self.transactions.pop(tx_hash, None)

    def remove_multiple_transactions(self, transactions: list[Transaction]) -> None:
        """
        Remove multiple transactions at once that were included in a mined/appended block.
        """
        for tx in transactions:
            self.transactions.pop(tx.tx_hash(), None)

    def get_transactions(self) -> list[Transaction]:
        """
        Return current mempool transactions as a list.
        """
        return list(self.transactions.values())
