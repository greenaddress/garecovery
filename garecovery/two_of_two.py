import logging
import json
import sys

from gaservices.utils import gacommon, gaconstants, txutil, b2h
import wallycore as wally

from . import clargs
from . import exceptions
from . import ga_xpub


class TwoOfTwo:

    def __init__(self, mnemonic, seed, nlocktime_file):
        logging.info('Reading nlocktime transactions from {}'.format(nlocktime_file))
        self.compressed_zip = open(nlocktime_file, "rb").read()

        self.mnemonic = mnemonic
        self.seed = seed
        version = wally.BIP32_VER_MAIN_PRIVATE
        self.wallet = wally.bip32_key_from_seed(self.seed, version, wally.BIP32_FLAG_SKIP_HASH)
        chaincode = wally.bip32_key_get_chain_code(self.wallet)

        zipdata = gacommon._unzip(self.compressed_zip, chaincode)
        if len(zipdata) == 0:
            raise exceptions.GARecoveryError(
                'The nlocktimes file "{}" contains no transactions'.format(nlocktime_file))
        self.txdata = [json.loads(txdata.decode("ascii")) for txdata in zipdata]

        self.fixup_old_nlocktimes()

        inferred_network = self.infer_network()
        if inferred_network != clargs.args.network:
            msg = 'Specified network and network inferred from nlocktime file do not match' \
                  '(specified={}, inferred={})'.format(clargs.args.network, inferred_network)
            raise exceptions.InvalidNetwork(msg)

    def fixup_old_nlocktimes(self):
        """Fixup data from old format nlocktimes files

        Older nlocktimes files do not contain explicit prevout_signatures, prevout_scripts or
        prevout_script_types. Detect this and extract them from the raw transaction to make the
        txdata look consistent to the rest of the code. Note that segwit is not being handled
        here because old style nlocktimes predate segwit
        """
        for txdata in self.txdata:
            if 'prevout_signatures' not in txdata:
                tx = txutil.from_hex(txdata['tx'])
                txdata['prevout_script_types'] = []
                txdata['prevout_signatures'] = []
                txdata['prevout_scripts'] = []
                for i in range(wally.tx_get_num_inputs(tx)):
                    inp = wally.tx_get_input_script(tx, i)
                    ga_signature = b2h(inp[2:inp[1]+2])
                    redeem_script = b2h(inp[-71:])
                    txdata['prevout_signatures'].append(ga_signature)
                    txdata['prevout_scripts'].append(redeem_script)
                    txdata['prevout_script_types'].append(gaconstants.P2SH_FORTIFIED_OUT)

    def infer_network(self):
        """Return the network inferred from the GreenAddress xpub found in the redeem script

        This is determined by generating the sets of possible GreenAddress public keys for each
        network (testnet/mainnet) and then searching for them in the redeem script
        """

        pointer = self.txdata[0]['prevout_pointers'][0]
        subaccount = self.txdata[0]['prevout_subaccounts'][0]

        def get_pubkey_for_pointer_hex(xpub):
            """Return hex encoded public key derived from xpub for pointer"""
            xpub = gacommon.derive_hd_key(xpub, [pointer], wally.BIP32_FLAG_KEY_PUBLIC)
            return b2h(wally.bip32_key_get_pub_key(xpub))

        def get_pubkeys_hex(fn, keys_material, network):
            """Return a list of hex-encoded public key given either a seed or a mnemonic"""
            xpubs = fn(keys_material, subaccount, network)
            return [get_pubkey_for_pointer_hex(xpub) for xpub in xpubs]

        def get_pubkeys_for_network_hex(network):
            """Return all the possible ga public keys (hex encoded) for the given network"""
            pubkeys_hex = get_pubkeys_hex(ga_xpub.xpubs_from_seed, self.seed, network)
            if self.mnemonic:
                pubkeys_hex.extend(
                    get_pubkeys_hex(ga_xpub.xpubs_from_mnemonic, self.mnemonic, network))
            return pubkeys_hex

        mainnet_xpubs = get_pubkeys_for_network_hex('mainnet')
        testnet_xpubs = get_pubkeys_for_network_hex('testnet')

        redeem_script = self.txdata[0]['prevout_scripts'][0]
        if any(xpub in redeem_script for xpub in mainnet_xpubs):
            return 'mainnet'
        if any(xpub in redeem_script for xpub in testnet_xpubs):
            return 'testnet'

        # Default to mainnet
        # Generally one of the derived xpubs will be found in the redeem script. It's possible
        # if the xpub was derived from the variant of the gait path using the mnemonic but a
        # hex seed was provided instead of a mnemonic when running the recovery tool that the key
        # will not be found. In this case default to mainnet.
        logging.warning("Unable to detect network. Defaulting to mainnet. Consider "
                        "passing the full mnemonic rather than hex seed")
        return 'mainnet'

    def _get_signed_tx(self, txdata):
        key = gacommon.derive_user_private_key(txdata, self.wallet, branch=1)
        return gacommon.countersign(txdata, key)

    def _get_private_key_wif(self, txdata, tx):
        # Newly created nlocktime files use branch 4, but some old ones may
        # have used branch 1, attempt both before failing.
        for branch in [4, 1]:
            key = gacommon.derive_user_private_key(txdata, self.wallet, branch)
            if self._private_key_can_spend_output(tx, key):
                return gacommon.private_key_to_wif(key, clargs.args.network)

        logging.error(';'.join(
            f'pointers:{t["prevout_pointers"]},subaccounts:{t["prevout_subaccounts"]},'
            for t in txdata))
        msg = 'The nlockime file contains inconsistent information, please contact support.'
        raise exceptions.GARecoveryError(msg)

    def _private_key_can_spend_output(self, tx, private_key):
        pubkey = wally.bip32_key_get_pub_key(private_key)
        spk_from_key = wally.scriptpubkey_p2pkh_from_bytes(pubkey, wally.WALLY_SCRIPT_HASH160)
        assert wally.tx_get_num_outputs(tx) == 1
        spk_from_tx = wally.tx_get_output_script(tx, 0)
        return spk_from_key == spk_from_tx

    def get_transactions(self):
        txs = []
        for txdata in self.txdata:
            tx = self._get_signed_tx(txdata)
            private_key_wif = self._get_private_key_wif(txdata, tx)
            txs.append((tx, private_key_wif))
        return txs
