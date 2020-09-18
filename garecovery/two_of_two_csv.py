import logging

import wallycore as wally

from garecovery import bitcoincore
from garecovery import clargs
from garecovery.exceptions import BitcoinCoreConnectionError, InsufficientFee, \
    MempoolRejectionError
from garecovery.ga_xpub import gait_paths_from_seed, gait_path_from_mnemonic
from garecovery.key import Bip32Key
from garecovery.subaccount import Green2of2Subaccount
from garecovery.utxo import SpendableUTXO
from garecovery.util import get_current_blockcount, get_feerate, scriptpubkey_from_address
from gaservices.utils import b2h_rev, h2b, h2b_rev
from gaservices.utils.gaconstants import CSV_BUCKETS, DUST_SATOSHI, EMPTY_TX_SIZE, INPUT_SIZE, \
    MAX_BIP125_RBF_SEQUENCE


class TwoOfTwoCSV(object):

    def __init__(self, mnemonic, seed):
        self.master_xprv = Bip32Key.from_seed(seed)
        self.gait_paths = gait_paths_from_seed(seed)
        if mnemonic:
            self.gait_paths.append(gait_path_from_mnemonic(mnemonic))

    def get_utxos(self, outputs):
        """Get utxos from a list of possible outputs"""
        core = bitcoincore.Connection(clargs.args)

        version = core.getnetworkinfo()["version"]
        if version < 190100:
            raise BitcoinCoreConnectionError('Unsupported version')

        if clargs.args.ignore_mempool:
            # using a descriptor with CSV is not possible
            scanobjects = [{'desc': 'addr({})'.format(o.address)} for o in outputs]
            result = core.scantxoutset('start', scanobjects)
            if not result['success']:
                raise BitcoinCoreConnectionError('scantxoutset failed')
            unspents = result['unspents']
        else:
            logging.info("Scanning from '{}'".format(clargs.args.scan_from))
            logging.warning('This step may take 10 minutes or more')

            # Need to import our keysets into core so that it will recognise the
            # utxos we are looking for
            addresses = [o.address for o in outputs]
            requests = [{
                'scriptPubKey': {'address': o.address},
                'timestamp': clargs.args.scan_from,
                'watchonly': True,
            } for o in outputs]
            logging.info('Importing {} derived addresses into bitcoind'.format(len(requests)))
            result = core.importmulti(requests)
            if result != [{'success': True}] * len(requests):
                raise exceptions.ImportMultiError('Unexpected result from importmulti')
            logging.info('Successfully imported {} derived addresses'.format(len(result)))

            current_blockcount = core.getblockcount()
            unspents = core.listunspent(0, 9999999, addresses)
            for u in unspents:
                # This may be inaccurate
                u['height'] = current_blockcount - u['confirmations']

        # match keys with utxos
        utxos = [SpendableUTXO(u, o)
                 for u in unspents
                 for o in outputs
                 if h2b(u['scriptPubKey']) == o.script_pubkey]

        logging.info('found {} utxos'.format(len(utxos)))
        return utxos

    def scan_subaccount(self, subaccount_pointer, pointer_search_depth):
        """Scan for utxos in a subaccount"""
        logging.info('subaccount {}: start scanning'.format(subaccount_pointer))
        utxos = []
        for gait_path in self.gait_paths:
            gait_path_hex = ''.join(hex(i+2**32)[-4:] for i in gait_path)
            logging.info('Using gait_path: {}'.format(gait_path_hex))
            subaccount = Green2of2Subaccount.from_master_xprv(
                self.master_xprv.xprv, gait_path, subaccount_pointer, clargs.args.network)

            start = 0
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

        estimated_vsize = EMPTY_TX_SIZE
        inputs, used_utxos = [], []

        for u in utxos:
            if not u.is_expired(blockcount):
                blocks_left = u.output.csv_blocks + u.height - blockcount
                logging.info('Skipping utxo ({}:{}) not expired ({} blocks left)'.format(
                    b2h_rev(u.txid), u.vout, blocks_left))
                continue

            estimated_vsize += INPUT_SIZE

            inputs.append({'txid': b2h_rev(u.txid), 'vout': u.vout})
            used_utxos.append(u)

        if len(used_utxos) == 0:
            return '', []

        logging.info('num used utxos: {}'.format(len(used_utxos)))

        feerate = get_feerate()
        satoshi_fee = round(feerate * estimated_vsize)

        satoshi_send = sum(u.satoshi for u in used_utxos) - satoshi_fee
        if satoshi_send < DUST_SATOSHI:
            raise InsufficientFee

        address = core.getnewaddress()
        scriptpubkey = scriptpubkey_from_address(address)

        tx = wally.tx_init(wally.WALLY_TX_VERSION_2, nlocktime, len(inputs), 1)
        sequence = MAX_BIP125_RBF_SEQUENCE
        if not is_replaceable:
            # A transaction is considered to have opted in to allowing
            # replacement of itself if any of its inputs have an nSequence
            # number less than or equal to MAX_BIP125_RBF_SEQUENCE
            sequence += 1

        for _input in inputs:
            txid = h2b_rev(_input['txid'])
            wally.tx_add_raw_input(tx, txid, _input['vout'], sequence, None, None, 0)

        wally.tx_add_raw_output(tx, satoshi_send, scriptpubkey, 0)

        transaction = wally.tx_to_hex(tx, wally.WALLY_TX_FLAG_USE_WITNESS)

        return transaction, used_utxos

    @staticmethod
    def sign_transaction(transaction, used_utxos):
        # TODO: use a wally_tx wrapper
        flags = wally.WALLY_TX_FLAG_USE_WITNESS
        tx = wally.tx_from_hex(transaction, flags)

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
        results = core.testmempoolaccept(transactions)
        logging.info('testmempoolaccept results {}'.format(results))
        # FIXME: consider filtering the unaccepted transactions instead of raising an error
        if not all(d.get('allowed') for d in results):
            raise MempoolRejectionError(
                'Transactions rejected from mempool ({})'.format(transactions))

    def get_transactions(self):
        """Get one transaction per subaccount which includes at least one recovered utxo and it is
        able to pay the fees"""
        transactions = []
        for subaccount_pointer in range((clargs.args.search_subaccounts or 0) + 1):
            utxos = self.scan_subaccount(subaccount_pointer, clargs.args.key_search_depth)
            if len(utxos) == 0:
                continue

            transaction, used_utxo = self.create_transaction(utxos)
            if transaction:
                signed_transaction = self.sign_transaction(transaction, used_utxo)
                transactions.append(signed_transaction)

        if transactions:
            self.test_transactions(transactions)

        logging.debug('transactions: {}'.format(transactions))
        flags = wally.WALLY_TX_FLAG_USE_WITNESS
        return [(wally.tx_from_hex(transaction, flags), None) for transaction in transactions]
