from garecovery.subaccount import Green2of2Subaccount
from garecovery.key import Bip32Key
from garecovery.utxo import SpendableElementsUTXO
from garecovery.ga_xpub import gait_paths_from_seed
from garecovery.exceptions import BitcoinCoreConnectionError, InsufficientFee, \
    MempoolRejectionError
from garecovery.util import get_current_blockcount
from garecovery import clargs
from garecovery import bitcoincore
from gaservices.utils import b2h, b2h_rev, h2b
from gaservices.utils.gaconstants import CSV_BUCKETS, LIQUID_EMPTY_TX_SIZE, LIQUID_OUTPUT_SIZE, \
    LIQUID_INPUT_SIZE

import logging
import wallycore as wally


class Liqugarecovery/bitcoin_config.pyidRecovery(object):

    def __init__(self, seed):
        self.seed = seed
        self.master_xprv = Bip32Key.from_seed(seed)
        # only 1st one as Liquid does not need to be backward compatible
        self.gait_path = gait_paths_from_seed(self.seed, latest_only=True)

    def get_utxos(self, outputs):
        """Get utxos from a list of possible outputs"""
        core = bitcoincore.Connection(clargs.args)

        version = core.getnetworkinfo()["version"]
        if version < 180101:
            raise BitcoinCoreConnectionError('Unsupported version')

        # using a descriptor with CSV is not possible
        scanobjects = [{'desc': 'addr({})'.format(o.address)} for o in outputs]
        result = core.scantxoutset('start', scanobjects)
        if not result['success']:
            raise BitcoinCoreConnectionError('scantxoutset failed')

        # add info for unblind
        for u in result['unspents']:
            blockhash = core.getblockhash(u['height'])
            tx_hex = core.getrawtransaction(u['txid'], False, blockhash)
            flags = wally.WALLY_TX_FLAG_USE_WITNESS | wally.WALLY_TX_FLAG_USE_ELEMENTS
            tx = wally.tx_from_hex(tx_hex, flags)
            u.update({
                'address': u['desc'][5:-10],  # stripping from "addr(<address>)#<8-char checksum>"
                'noncecommitment': b2h(wally.tx_get_output_nonce(tx, u['vout'])),
                'rangeproof': b2h(wally.tx_get_output_rangeproof(tx, u['vout'])),
            })

        # unblind and match keys with utxos
        utxos = [SpendableElementsUTXO(u, o, self.seed)
                 for u in result['unspents']
                 for o in outputs
                 if h2b(u['scriptPubKey']) == o.script_pubkey]

        logging.info('found {} utxos'.format(len(utxos)))
        return utxos

    def scan_subaccount(self, subaccount_pointer, pointer_search_depth):
        """Scan for utxos in a subaccount"""
        subaccount = Green2of2Subaccount.from_master_xprv(
            self.master_xprv.xprv, self.gait_path, subaccount_pointer, clargs.args.network)
        logging.info('subaccount {}: start scanning'.format(subaccount_pointer))

        start = 0
        utxos = []
        while True:
            logging.info('subaccount {}: range {}-{}'.format(
                subaccount_pointer, start, start + pointer_search_depth))
            outputs = []
            for pointer in range(start, start + pointer_search_depth):
                for csv_blocks in CSV_BUCKETS[clargs.args.network]:
                    outputs.append(subaccount.get_csv_output(pointer, csv_blocks))

            new_utxos = self.get_utxos(outputs)
            logging.info('subaccount {}: found {} new utxos'.format(
                subaccount_pointer, len(new_utxos)))

            if not new_utxos:
                break

            utxos += new_utxos
            start += pointer_search_depth

        logging.info('subaccount {}: stop scanning'.format(subaccount_pointer))
        return utxos

    # TODO: transaction may be too big, allow to split it
    @staticmethod
    def create_transaction(utxos):
        core = bitcoincore.Connection(clargs.args)

        nlocktime = blockcount = get_current_blockcount() or 0
        is_replaceable = True

        balance = {}
        estimated_vsize = LIQUID_EMPTY_TX_SIZE
        inputs, used_utxos = [], []
        input_assets, input_values, input_abfs, input_vbfs = [], [], [], []

        for u in utxos:
            if not u.is_expired(blockcount):
                blocks_left = u.output.csv_blocks + u.height - blockcount
                logging.info('Skipping utxo ({}:{}) not expired ({} blocks left)'.format(
                    b2h_rev(u.txid), u.vout, blocks_left))
                continue

            asset = b2h_rev(u.asset)
            if asset not in balance:
                balance.update({asset: u.value})
                estimated_vsize += (LIQUID_INPUT_SIZE + LIQUID_OUTPUT_SIZE)
            else:
                balance.update({asset: balance[asset] + u.value})
                estimated_vsize += LIQUID_INPUT_SIZE

            inputs.append({'txid': b2h_rev(u.txid), 'vout': u.vout})
            input_assets.append(b2h_rev(u.asset))
            input_values.append(round(10**-8 * u.value, 8))
            input_abfs.append(b2h_rev(u.abf))
            input_vbfs.append(b2h_rev(u.vbf))
            used_utxos.append(u)

        if len(used_utxos) == 0:
            return '', []

        logging.info('num used utxos: {}'.format(len(used_utxos)))

        policy_asset = core.dumpassetlabels()['bitcoin']
        if policy_asset not in balance:
            raise InsufficientFee('found assets ({}) but there are no fees to spend them'.format(
                list(balance.keys())))

        # TODO: allow different fee rates
        feerate = float(core.getnetworkinfo().get('relayfee', 0.00001))
        fee = round(feerate * estimated_vsize * 10**-3, 8)

        map_amount = {'fee': fee}
        map_asset = {}
        for asset, value in balance.items():
            value_btc = round(10**-8 * value, 8)
            if asset == policy_asset:
                if value_btc <= fee:
                    raise InsufficientFee
                # FIXME: consider trying to avoid floats
                value_btc = round(value_btc - fee, 8)

            # FIXME: ideally we should accept either a list of addresses or an xpub/descriptor
            address = core.getnewaddress()
            map_amount.update({address: value_btc})
            map_asset.update({address: asset})

        # use core rpc instead of wally mainly to delegate random number generation
        transaction = core.createrawtransaction(
            inputs,
            map_amount,
            nlocktime,
            is_replaceable,
            map_asset)

        # Note that if an output is unblinded the following call removes the nonce commitment
        blinded_transaction = core.rawblindrawtransaction(
            transaction,
            input_vbfs,
            input_values,
            input_assets,
            input_abfs)

        return blinded_transaction, used_utxos

    @staticmethod
    def sign_transaction(blinded_transaction, used_utxos):
        # TODO: use a wally_tx wrapper
        flags = wally.WALLY_TX_FLAG_USE_WITNESS | wally.WALLY_TX_FLAG_USE_ELEMENTS
        tx = wally.tx_from_hex(blinded_transaction, flags)

        # All sequence numbers must be set before signing
        for index, u in enumerate(used_utxos):
            u.set_csv_sequence(tx, index)

        blockcount = get_current_blockcount() or 0
        for index, u in enumerate(used_utxos):
            assert u.is_expired(blockcount)
            logging.debug('signing {}-th input'.format(index))
            u.sign(tx, index)

        logging.debug('signed tx: {}'.format(wally.tx_to_hex(tx, flags)))
        return wally.tx_to_hex(tx, flags)

    @staticmethod
    def test_transactions(transactions):
        logging.info('testing {} transactions against mempool'.format(len(transactions)))
        core = bitcoincore.Connection(clargs.args)
        result = []
        for transaction in transactions:
            # TODO: once core allows it, pass all transactions at once
            result += core.testmempoolaccept([transaction])
            logging.info('testmempoolaccept results {}'.format(result[-1]))
        # FIXME: consider filtering the unaccepted transactions instead of raising an error
        if not all(d.get('allowed') for d in result):
            raise MempoolRejectionError(
                'One or more txs rejected from mempool ({})'.format(transactions))

    def get_transactions(self):
        """Get one transaction per subaccount which includes at least one recovered utxo and it is
        able to pay the fees"""
        transactions = []
        for subaccount_pointer in range((clargs.args.search_subaccounts or 0) + 1):
            utxos = self.scan_subaccount(subaccount_pointer, clargs.args.key_search_depth)
            if not utxos:
                continue
            unblinded_utxos = [u for u in utxos if u.is_unblinded()]
            if unblinded_utxos:
                logging.warning('Found {} unblinded utxos.'.format(len(unblinded_utxos)))
            if not clargs.args.split_unblinded_inputs and unblinded_utxos:
                logging.warning('You may want to create two transactions with '
                                '--split-unblinded-inputs')
                utxo_sets = [utxos]
            else:
                utxos = [u for u in utxos if u not in unblinded_utxos]
                utxo_sets = [utxos, unblinded_utxos]

            for us in utxo_sets:
                transaction, used_utxo = self.create_transaction(us)
                if transaction:
                    signed_transaction = self.sign_transaction(transaction, used_utxo)
                    transactions.append(signed_transaction)

        if transactions:
            self.test_transactions(transactions)

        logging.debug('transactions: {}'.format(transactions))
        flags = wally.WALLY_TX_FLAG_USE_WITNESS | wally.WALLY_TX_FLAG_USE_ELEMENTS
        return [(wally.tx_from_hex(tx, flags), None) for tx in transactions]
