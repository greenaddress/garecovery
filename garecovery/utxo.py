import wallycore as wally


class ElementsUTXO(object):
    """Elements UTXO"""

    def __init__(self, unspent):
        """Create ElementsUTXO from scanutxoset (processed) output"""
        self.txid = wally.hex_to_bytes(unspent.get('txid'))[::-1]
        self.vout = unspent.get('vout')
        self.script_pubkey = wally.hex_to_bytes(unspent.get('scriptPubKey'))
        self.address = unspent.get('address')
        self.height = unspent.get('height')

        # blinded data
        is_unblinded = 'asset' in unspent and 'amount' in unspent
        self.asset = wally.hex_to_bytes(unspent['asset'])[::-1] if is_unblinded else None
        self.value = round(unspent['amount'] * 10**8) if is_unblinded else None
        self.abf = b'\x00' * 32 if self.asset else None
        self.vbf = b'\x00' * 32 if self.value else None

        self.asset_commitment = \
            b'\x01' + self.asset if is_unblinded else \
            wally.hex_to_bytes(unspent.get('assetcommitment'))
        self.value_commitment = \
            wally.tx_confidential_value_from_satoshi(self.value) if is_unblinded else \
            wally.hex_to_bytes(unspent.get('amountcommitment'))
        self.nonce_commitment = \
            b'' if is_unblinded else \
            wally.hex_to_bytes(unspent.get('noncecommitment'))
        self.rangeproof = \
            b'' if is_unblinded else \
            wally.hex_to_bytes(unspent.get('rangeproof'))

    def unblind(self, private_blinding_key):
        if self.is_unblinded():
            return
        self.value, self.asset, self.abf, self.vbf = wally.asset_unblind(
            self.nonce_commitment, private_blinding_key, self.rangeproof, self.value_commitment,
            self.script_pubkey, self.asset_commitment)

    def is_unblinded(self):
        return 1 == self.asset_commitment[0] == self.value_commitment[0]


class SpendableElementsUTXO(ElementsUTXO):
    """Elements unblinded UTXO able to spend itself"""

    def __init__(self, unspent, output, seed):
        super().__init__(unspent)
        if output.address != self.address:
            raise ValueError('addresses must match: {}, {}'.format(output.address, self.address))
        self.output = output
        self.unblind(output.get_private_blinding_key(seed))

    def is_expired(self, blockcount):
        if not hasattr(self.output, 'csv_blocks'):
            return True
        return (blockcount - self.height) >= self.output.csv_blocks

    def set_csv_sequence(self, tx, index):
        """Set the sequence number with csv_blocks"""
        wally.tx_set_input_sequence(tx, index, self.output.csv_blocks)

    def sign(self, tx, index):
        """Sign the index-th input of tx, fill its witness and scriptSig assuming CSV time is
        expired"""

        txhash = wally.tx_get_elements_signature_hash(
            tx,
            index,
            self.output.witness_script,
            self.value_commitment,
            wally.WALLY_SIGHASH_ALL,
            wally.WALLY_TX_FLAG_USE_WITNESS)

        wally.tx_set_input_witness(tx, index, self.output.get_signed_witness(txhash))
        wally.tx_set_input_script(tx, index, self.output.script_sig)
