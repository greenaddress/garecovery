import decimal
import io
import logging
import math
import os
import shutil
import time

import pycoin.tx
import pycoin.ui
import pycoin.key.BIP32Node
import pycoin.key.Key
import pycoin.encoding

from gaservices.utils import gacommon

from wallycore import *

from . import bitcoincore
from . import clargs
from . import exceptions
from . import ga_xpub
from . import util


satoshi_per_btc = decimal.Decimal(1e8)


HARDENED = 0x80000000


MAX_BIP125_RBF_SEQUENCE = 0xfffffffd


def get_scriptpubkey_hex(redeem_script_hash_hex):
    """Return a 2of3 multisig script pub key as a hex string"""
    return "a914{}87".format(redeem_script_hash_hex)


def get_redeem_script(keys):
    """Return a 2of3 multisig redeem script as a hex string"""
    keys = [hex_from_bytes(key) for key in keys]
    logging.debug("get_redeem_script public keys = {}".format(keys))
    return hex_to_bytes("5221{}21{}21{}53ae".format(*keys))


def bip32_key_from_base58check(base58check):
    raw = base58check_to_bytes(base58check)
    return bip32_key_unserialize(raw)


def derive_user_key(wallet, subaccount, branch=1):
    subaccount_path = gacommon.get_subaccount_path(subaccount)
    return gacommon.derive_hd_key(wallet, subaccount_path + [branch, ])


def get_virtual_tx_size(tx):
    """Return the virtual transaction size as defined in BIP141"""
    def streamed_size(tx, include_witness_data):
        """Return the streamed size of a tx, optionally with witness data"""
        buffer_ = io.BytesIO()
        tx.stream(buffer_, include_witness_data=include_witness_data)
        return len(buffer_.getvalue())
    base_tx_size = streamed_size(tx, include_witness_data=False)
    total_tx_size = streamed_size(tx, include_witness_data=True)
    tx_weight = base_tx_size * 3 + total_tx_size
    return int(math.ceil(tx_weight / 4.0))


class P2SH:

    type_ = 'p2sh'

    def __init__(self, pubkeys, testnet):
        self.redeem_script = get_redeem_script(pubkeys)
        self.redeem_script_hex = hex_from_bytes(self.redeem_script)

        script_hash = hash160(self.get_witness_script())
        script_hash_hex = hex_from_bytes(script_hash)
        self.scriptPubKey = get_scriptpubkey_hex(script_hash_hex)

        ver = b'\xc4' if testnet else b'\x05'
        self.address = base58check_from_bytes(ver + script_hash)

    def get_witness_script(self):
        return self.redeem_script


class P2WSH(P2SH):

    type_ = 'p2wsh'

    def __init__(self, pubkeys, testnet):
        P2SH.__init__(self, pubkeys, testnet)

    def get_witness_script(self):
        return hex_to_bytes('0020') + sha256(self.redeem_script)


def createDerivedKeySet(ga_xpub, wallets, custom_xprv, testnet):
    """Return class instances which represent sets of derived keys

    Given a user's key material call createDerivedKeySet to create a class
    instances of which can be created by specifying the pointer value. Each
    such instance then represents a set of keys derived on the path specified
    by that pointer.
    """
    # The GreenAddress extended public key (ga_xpub) also contains the subaccount index encoded
    # as the child_num
    subaccount = bip32_key_get_child_num(ga_xpub)

    # Given the subaccount the user keys can be derived. Optionally the user may provide a custom
    # extended private key as the backup
    user_keys = [derive_user_key(wallet, subaccount) for wallet in wallets]
    if custom_xprv:
        logging.debug("Using custom xprv")
        root_xprv = bip32_key_from_base58check(custom_xprv)
        branch = 1
        xprv = gacommon.derive_hd_key(root_xprv, [branch, ], BIP32_FLAG_KEY_PRIVATE)
        user_keys.append(xprv)
    assert len(user_keys) == 2

    class DerivedKeySet:
        """Represent sets of HD keys
        """

        def __init__(self, pointer):
            logging.debug('Derive keys for subaccount={}, pointer={}'.format(subaccount, pointer))

            self.subaccount = subaccount
            self.pointer = pointer

            # Derive the GreenAddress public key for this pointer value
            ga_key = gacommon.derive_hd_key(ga_xpub, [pointer, ], BIP32_FLAG_KEY_PUBLIC)
            self.ga_key = bip32_key_get_pub_key(ga_key)
            logging.debug("ga_key = {}".format(hex_from_bytes(self.ga_key)))

            # Derive the user private keys for this pointer value
            flags = BIP32_FLAG_KEY_PRIVATE
            user_key_paths = [(key, [pointer, ]) for key in user_keys]
            private_keys = [gacommon.derive_hd_key(*path, flags=flags) for path in user_key_paths]
            self.private_keys = [bip32_key_get_priv_key(key) for key in private_keys]

            # Derive the user public keys from the private keys
            user_public_keys = [ec_public_key_from_private_key(key) for key in self.private_keys]
            public_keys = [self.ga_key, ] + user_public_keys

            # Script could be segwit or not - generate both segwit and non-segwit addresses
            self.witnesses = {cls.type_: cls(public_keys, testnet) for cls in (P2SH, P2WSH)}
            logging.debug('p2sh address: {}'.format(self.witnesses['p2sh'].address))
            logging.debug('p2wsh address: {}'.format(self.witnesses['p2wsh'].address))

    return DerivedKeySet


class UTXO:

    def __init__(self, keyset, witness_type, vout, tx, dest_address):
        self.keyset = keyset
        self.vout = vout
        self.tx = tx
        assert self.vout < len(self.tx.txs_out)
        self.dest_address = dest_address
        self.witness = self.keyset.witnesses[witness_type]

    def get_default_feerate(self):
        """Get a value for default feerate.

        On testnet only it is possible to pass --default-feerate as an option. On mainnet this is
        not supported as it is too error prone.
        """
        default_feerate = clargs.args.default_feerate
        if not is_testnet_address(self.dest_address):
            # For non-testnet addresses do not support --default-feerate
            msg = 'Unable to get fee rate from core'
            if default_feerate:
                msg = msg + ' (ignoring --default-feerate on mainnet)'
            raise exceptions.NoFeeRate(msg)

        if default_feerate is None:
            msg = 'Unable to get fee rate from core, you must pass --default-feerate'
            raise exceptions.NoFeeRate(msg)

        fee_satoshi_byte = decimal.Decimal(default_feerate)
        return fee_satoshi_byte

    def get_feerate(self):
        """Return the required fee rate in satoshis per byte"""
        logging.debug("Connecting to bitcoinrpc to get feerate")
        core = bitcoincore.Connection(clargs.args)

        blocks = clargs.args.fee_estimate_blocks

        fee_btc_kb = core.estimatesmartfee(blocks)['feerate']
        if fee_btc_kb == -1:
            # estimatesmartfee returns -1 to indicate it is unable to provide a fee estimate
            fee_satoshi_byte = self.get_default_feerate()
        else:
            fee_satoshi_kb = fee_btc_kb * satoshi_per_btc
            fee_satoshi_byte = round(fee_satoshi_kb / 1000)

            logging.debug('feerate = {} BTC/kb'.format(fee_btc_kb))
            logging.debug('feerate = {} satoshis/kb'.format(fee_satoshi_kb))

        logging.info('Fee estimate for confirmation in {} blocks is '
                     '{} satoshis/byte'.format(blocks, fee_satoshi_byte))

        return fee_satoshi_byte

    def get_raw_unsigned(self, fee_satoshi):
        """Return raw transaction ready for signing

        May return a transaction with amount=0 if the input amount is not enough to cover fees
        """
        txout = self.tx.txs_out[self.vout]
        amount_satoshi = txout.coin_value

        if fee_satoshi >= amount_satoshi:
            logging.warning('Insufficient funds to cover fee')
            logging.warning('txout has value of {}, fee = {}'.format(amount_satoshi, fee_satoshi))

        # Calculate adjusted amount = input amount - fee
        adjusted_amount_satoshi = max(0, amount_satoshi - fee_satoshi)
        logging.debug('tx amount = amount - fee = {} - {} = {}'.format(
            amount_satoshi, fee_satoshi, adjusted_amount_satoshi))
        assert adjusted_amount_satoshi >= 0
        adjusted_amount_btc = decimal.Decimal(adjusted_amount_satoshi)/satoshi_per_btc

        logging.debug("Create tx: {} sat -> {}".format(adjusted_amount_satoshi, self.dest_address))
        logging.info("Input tx id = {}, vout={}".format(self.tx.id().encode("ascii"), self.vout))
        txin = pycoin.tx.TxIn(self.tx.hash(), self.vout, sequence=MAX_BIP125_RBF_SEQUENCE)
        scriptPubKey = pycoin.ui.script_obj_from_address(self.dest_address)
        txout = pycoin.tx.TxOut(adjusted_amount_satoshi, scriptPubKey.script())

        # Set nlocktime to the current blockheight to discourage 'fee sniping', as per the core
        # wallet implementation
        nlocktime = util.get_current_blockcount() or 0

        version = 1
        tx = pycoin.tx.Tx(version, [txin, ], [txout, ], nlocktime)
        return tx.as_hex()

    def get_fee(self, tx):
        """Given a raw transaction return the fee"""
        virtual_tx_size = get_virtual_tx_size(tx)
        logging.debug("virtual transaction size = {}".format(virtual_tx_size))
        fee_satoshi_byte = self.get_feerate()
        fee_satoshi = fee_satoshi_byte * virtual_tx_size
        logging.debug('Calculating fee over {} (virtual) byte tx @{} satoshi per '
                      'byte = {} satoshis'.format(virtual_tx_size, fee_satoshi_byte, fee_satoshi))
        return fee_satoshi

    def sign(self):
        """Return raw signed transaction"""
        type_map = {'p2wsh': gacommon.SEGWIT, 'p2sh': 0}
        txdata = {
            'prevout_scripts': [self.witness.redeem_script_hex, ],
            'prevout_script_types': [type_map[self.witness.type_], ],
            'prevout_values': [self.tx.txs_out[self.vout].coin_value, ],
        }
        signatories = [gacommon.ActiveSignatory(key) for key in self.keyset.private_keys]

        def sign_(fee):
            txdata['tx'] = self.get_raw_unsigned(fee)
            return gacommon.sign(
                txdata,
                signatories,
            )

        signed_no_fee = sign_(fee=1000)
        fee_satoshi = self.get_fee(signed_no_fee)
        signed_fee = sign_(fee=fee_satoshi)
        return signed_fee.as_hex()


def is_testnet_address(address):
    try:
        key = pycoin.key.Key.from_text(address)
        netcode = key.netcode()
        return netcode != 'BTC'
    except pycoin.encoding.EncodingError:
        return True


class TwoOfThree(object):

    def __init__(self, mnemonic, wallet, backup_wallet, custom_xprv):
        self.mnemonic = mnemonic
        self.wallets = [wallet, ]
        self.custom_xprv = custom_xprv

        if backup_wallet:
            self.wallets.append(backup_wallet)
        else:
            assert self.custom_xprv
            logging.info('Using custom xprv = {}'.format(self.custom_xprv))

        self.is_testnet = self._is_testnet()

    def get_destination_address(self):
        """Return the destination address to recover funds to"""
        return clargs.args.destination_address

    def _is_testnet(self):
        """Return true if the destination address is a testnet address"""
        return is_testnet_address(self.get_destination_address())

    def scan_blockchain(self, keysets):
        # Blockchain scanning is delegated to core via bitcoinrpc
        logging.debug("Connecting to bitcoinrpc to scan blockchain")
        core = bitcoincore.Connection(clargs.args)

        logging.info("Scanning from '{}'".format(clargs.args.scan_from))
        logging.warning('This step may take 10 minutes or more')

        # Need to import our keysets into core so that it will recognise the
        # utxos we are looking for
        addresses = []
        requests = []
        for keyset in keysets:
            for witness in keyset.witnesses.values():
                addresses.append(witness.address)
                requests.append({
                    'scriptPubKey': {"address": witness.address},
                    'timestamp': clargs.args.scan_from,
                    'watchonly': True,
                })
        logging.info('Importing {} derived addresses into bitcoind'.format(len(requests)))
        result = core.importmulti(requests)
        expected_result = [{'success': True}, ] * len(requests)
        if result != expected_result:
            logging.warning('Unexpected result from importmulti')
            logging.warning('Expected: {}'.format(expected_result))
            logging.warning('Actual: {}'.format(result))
            raise exceptions.ImportMultiError('Unexpected result from importmulti')
        logging.info('Successfully imported {} derived addresses'.format(len(result)))

        # Scan the blockchain for any utxos with addresses that match the derived keysets
        logging.info('Getting unspent transactions...')
        all_utxos = core.listunspent(0, 9999999, addresses)
        logging.debug('all utxos = {}'.format(all_utxos))
        logging.info('There are {} unspent transactions'.format(len(all_utxos)))

        # Now need to match the returned utxos with the keysets that unlock them
        # This is a rather unfortunate loop because there is no other way to correlate the
        # results from listunspent with the requests to importmulti
        utxos = []
        tx_matches = [(tx['txid'], keyset, witness, tx['vout'])
                      for tx in all_utxos
                      for keyset in keysets
                      for witness in keyset.witnesses.values()
                      if tx['scriptPubKey'] == witness.scriptPubKey]

        raw_txs = core.batch_([["getrawtransaction", tx[0]] for tx in tx_matches])
        dest_address = self.get_destination_address()
        for txid_match, raw_tx in zip(tx_matches, raw_txs):
            txid, keyset, witness, txvout = txid_match
            logging.info('Found recoverable transaction, '
                         'subaccount={}, pointer={}, txid={}, witness type={}'.
                         format(keyset.subaccount, keyset.pointer, txid,
                                witness.type_))
            logging.debug("found raw={}".format(raw_tx))
            tx_ = pycoin.tx.Tx.from_hex(raw_tx)
            utxo = UTXO(
                keyset,
                witness.type_,
                txvout,
                tx_,
                dest_address,
            )
            utxos.append(utxo)
        return utxos

    def _derived_keyset(self, ga_xpub):
        """Call createDerivedKeySet with ga_xpub"""
        return createDerivedKeySet(ga_xpub, self.wallets, self.custom_xprv, self.is_testnet)

    def get_keysets(self, subaccounts, pointers):
        """Return the keysets for a set of subaccounts/pointers"""
        # There are two options here:
        # 1) If the GreenAddress extended public key (ga_xpub) has been specified then not only
        #    does it not need to be derived but it also contains within its serialization format
        #    the subaccount index (in the child_num field)
        # 2) If ga_xpub is not given it's possible to iterate over the possible values of
        #    subaccount and build a larger search space. This is suboptimal
        if clargs.args.search_subaccounts:
            logging.warn('No --ga-xpub specified, deriving and iterating over possible subaccounts')
            keyset_factories = []
            for subaccount in range(*subaccounts):
                xpubs = ga_xpub.xpubs_from_mnemonic(self.mnemonic, subaccount, self.is_testnet)
                keyset_factories.extend([self._derived_keyset(xpub) for xpub in xpubs])
        else:
            assert clargs.args.ga_xpub
            xpub = bip32_key_from_base58check(clargs.args.ga_xpub)
            keyset_factories = [self._derived_keyset(xpub), ]

        return [DerivedKeySet(pointer)
                for DerivedKeySet in keyset_factories
                for pointer in range(*pointers)]

    def get_utxos(self, subaccounts, pointers):
        keysets = self.get_keysets(subaccounts, pointers)
        return self.scan_blockchain(keysets)

    def rescan(self, pointer_search_depth, num_subaccounts):
        pointers = (0, pointer_search_depth)
        subaccounts = (1, 1 + num_subaccounts)

        utxos = []
        while True:
            logging.info("Scanning subaccount {}->{}, pointers {}->{}".format(
                subaccounts[0], subaccounts[1], pointers[0], pointers[1]))

            next_utxos = self.get_utxos(subaccounts, pointers)
            if not next_utxos:
                logging.info('No transactions found, stopping scan')
                break

            # As long as some utxos have been found in the range (pointers), keep scanning
            logging.info('Found {} transactions'.format(len(next_utxos)))
            utxos.extend(next_utxos)
            pointers = (pointers[1], pointers[1] + pointer_search_depth)

        return utxos

    def sign_utxos(self):
        logging.debug("signing {} utxos...".format(len(self.utxos)))
        return [utxo.sign() for utxo in self.utxos]

    def get_transactions(self):
        # Get a list of utxos by scanning the blockchain
        self.utxos = self.rescan(
            clargs.args.key_search_depth,
            clargs.args.search_subaccounts or 0)

        raw_txs = self.sign_utxos()
        return [pycoin.tx.Tx.from_hex(raw_tx) for raw_tx in raw_txs]
