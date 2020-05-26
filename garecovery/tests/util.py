import csv
import mock
import os
import sys
import wallycore as wally

try:
    # Python 2
    import StringIO as io
    import exceptions as exc
except ImportError:
    # Python 3
    import io
    import builtins as exc

from garecovery.recoverycli import main
from garecovery.clargs import DEFAULT_OFILE
from gaservices.utils import txutil, gaconstants


TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), 'test_data')


mock_addresses = [
  {
    'address': 'AzpjuSThJLcyJFrXZDXstHU8uvq8EDDPBTzQvAQuNVbZaisSjYX1HMEMjaoLz2AphkJ2wfmFwRGhyako',
    'unconfidential_address': 'XKMc3Zqa2eqzDCJ2u9y1vUBnC7o1p3WnKh',
    'scriptpubkey': 'a91457d2b3591fe27661d0a785967126abf9ed19999d87',
    'public_blinding_key': '02227fe08e840120991db5115cce32162897bdd73012e3858715d5f94ad74113cb',
  },
  {
    'address': 'Azppoxtn14x4niJRxnhEmQNY7qiEoUM8gcVrc6MASVTey9e3ZzxK7Q4riJyxgfq2ySjM6qh2L2TetpvL',
    'unconfidential_address': 'XWypf6BiGS9DW72gJ3unU1vp41PA7z4ZJx',
    'scriptpubkey': 'a914d7559651b007d4971de281f81347653fa8cf9e0087',
    'public_blinding_key': '02d7a477cbcd56ae33a7b6917e10e41a80168b590b23775546a4ea26a977f178e7',
  },
]


# Patch os.path.exists so that it returns False whenever asked if the default output file exists,
# otherwise all tests will fail by default
def path_exists(filename):
    if filename == DEFAULT_OFILE:
        return False
    return _path_exists(filename)


_path_exists = os.path.exists


# Do not read bitcoin config files from filesystem during testing
def raise_IOError(*args):
    raise IOError()


def datafile(filename):
    return os.path.join(TEST_DATA_DIR, filename)


def read_datafile(filename):
    return open(datafile(filename)).read().strip()


def accumulate_widths(iterable):
    total = 0
    for i in iterable:
        yield total
        total += i + 1


def parse_summary(output):
    """Parse verbatim summary output and return a dict

    The summary is expected to consist of:
    (line 0) Column headings
    (line 1) Some kind of underline which also indicates the column width
    (line 2:-3) Data
    (line -1) A total

    Return a list of dicts of {heading: value}
    """
    lines = output.split('\n')

    underlines = lines[1]
    widths = [len(underline) for underline in underlines.split()]
    starts = accumulate_widths(widths)
    fields = list(zip(starts, widths))

    def split_row(row):
        data = [row[start:start + width] for start, width in fields]
        data = [datum.strip() for datum in data]
        return data

    headings = lines[0]
    headings = split_row(headings)

    return [dict(list(zip(headings, split_row(line)))) for line in lines[2:-3]]


def parse_csv(output):
    """Parse csv output"""
    return csv.DictReader(io.StringIO(output))


def get_argparse_error(args):
    """When argparse raises an error it writes to stderr and does a sys.exit"""
    with mock.patch('sys.stderr', io.StringIO()) as output:
        try:
            result = main([sys.argv[0], ] + args)
            raise Exception("Expected a fail")
        except exc.SystemExit:
            pass
    return output.getvalue()


class ContextualStringIO(io.StringIO):

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def get_output_ex(args, expect_error=False, is_liquid=False):
    ofiles = {}

    def recovery_open_(filename, mode=None):
        if 'test_data' in filename and mode is None:
            return open(filename)
        else:
            if mode is 'w':
                ofile = ContextualStringIO()
                ofiles[filename] = ofile
                return ofile

    with mock.patch('garecovery.recoverycli.open', side_effect=recovery_open_):
        with mock.patch('sys.stdout', io.StringIO()) as output:
            result = main([sys.argv[0], ] + args, is_liquid)
            if expect_error:
                assert result != 0, output.getvalue()
            else:
                assert result == 0, output.getvalue()

        # Convert StringIOs in ofiles to string content for convenience
        ofiles = {filename: ofiles[filename].getvalue() for filename in ofiles}
        return output.getvalue(), ofiles


def get_output(args, expect_error=False, is_liquid=False):
    """Patch sys.stdout and call main with args capturing the output

    This is now a legacy call for backwards compatibility of old tests
    """
    filtered_args = []
    nlocktime = False
    show_summary = False
    for arg in args:
        if arg in ['--show-summary', '-s']:
            show_summary = True
        else:
            if arg == '2of2':
                nlocktime = True
        filtered_args.append(arg)

    output, ofiles = get_output_ex(filtered_args, expect_error, is_liquid)

    if expect_error:
        return output

    if show_summary:
        # the summary view is backward compatible automatically
        return output
    else:
        # In legacy mode if you did not pass --show-summary you got raw output depending on the
        # recovery mode. Can use the csv output to reconstruct it
        csv_content = ofiles[DEFAULT_OFILE]
        csv_ = csv.DictReader(io.StringIO(csv_content))
        if not nlocktime:
            # simply the raw transactions
            lines = [row['raw tx'] for row in csv_]
            return '\n'.join(lines)
        else:
            # in 2of2 nlocktime you got the raw tx but also the private key
            lines = ["{} {}".format(row['raw tx'], row['private key']) for row in csv_]
            return '\n'.join(lines)


def verify_txs(txs, utxos, expect_witness):

    txs = [txutil.from_hex(tx) for tx in txs]

    for tx in txs:
        assert wally.tx_get_num_inputs(tx) == 1
        assert wally.tx_get_num_outputs(tx) >= 1
        if expect_witness:
            assert wally.tx_get_witness_count(tx) == 1
        else:
            assert wally.tx_get_witness_count(tx) == 0
        wally.tx_get_total_output_satoshi(tx)  # Throws if total overflows

    assert len(utxos) > 0
    for idx, utxo in enumerate(utxos):
        tx = txs[idx]
        spending_tx = txutil.from_hex(''.join(utxo.split()))
        # FIXME: Test that spending_tx is signed correctly


class AuthServiceProxy:
    """Mock bitcoincore"""

    lbtc_hex = 'b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23'

    def tx_from_hex(self, tx_hex):
        flags = wally.WALLY_TX_FLAG_USE_WITNESS
        if self.is_liquid:
            flags |= wally.WALLY_TX_FLAG_USE_ELEMENTS
        return wally.tx_from_hex(tx_hex, flags)

    @staticmethod
    def tx_to_hex(tx):
        return wally.tx_to_hex(tx, wally.WALLY_TX_FLAG_USE_WITNESS)

    def __init__(self, txfile, is_liquid=False):
        self.is_liquid = is_liquid
        versions = gaconstants.ADDR_VERSIONS_LIQUID_REGTEST if is_liquid else \
            gaconstants.ADDR_VERSIONS_TESTNET
        family = gaconstants.ADDR_FAMILY_LIQUID_REGTEST if is_liquid else \
            gaconstants.ADDR_FAMILY_TESTNET
        self.given_addresses = 0
        self.tx_by_id = {}
        self.txout_by_address = {}
        for line in open(datafile(txfile)).readlines():
            tx_data = line.strip().split()
            tx_hex = tx_data[0]
            tx = self.tx_from_hex(tx_hex)
            self.tx_by_id[txutil.get_txhash_hex(tx)] = tx
            for i in range(wally.tx_get_num_outputs(tx)):
                addr = txutil.get_output_address(tx, i, versions, family)
                self.txout_by_address[addr] = [tx, i]
                if is_liquid:
                    _, amount, asset, a_bl, v_bl, conf = tx_data
                    self.txout_by_address[addr] += [amount, asset, a_bl, v_bl, conf]
                    # for simplicity liquid mockup tx have one output
                    assert wally.tx_get_num_outputs(tx) == 1
        self.imported = {}

        # This is something of a workaround because all the existing tests are based on generating
        # txs where nlocktime was fixed as 0. The code changed to use current blockheight, so by
        # fudging this value to 0 the existing tests don't notice the difference
        self.getblockcount.return_value = 0

        self.getnetworkinfo.return_value = {'version': 160000}

    def importmulti(self, requests):
        result = []
        for request in requests:
            if not self.is_liquid:
                assert request['watchonly'] is True
                address = request['scriptPubKey']['address']
            else:
                scriptpubkey = wally.hex_to_bytes(request['scriptPubKey'])
                assert wally.scriptpubkey_get_type(scriptpubkey) == wally.WALLY_SCRIPT_TYPE_P2SH
                address = wally.base58check_from_bytes(
                    bytearray([gaconstants.ADDR_VERSIONS_LIQUID_REGTEST[1]]) + scriptpubkey[2:22])

            if address in self.txout_by_address:
                self.imported[address] = self.txout_by_address[address]
            result.append({'success': True})
        return result

    def _get_unspent(self, address):
        imported = self.imported.get(address, None)
        if imported is None:
            return None
        tx, i = imported[:2]
        scriptpubkey = wally.tx_get_output_script(tx, i)
        ret = {
            "txid": txutil.get_txhash_hex(tx),
            "vout": i,
            "address": address,
            "scriptPubKey": wally.hex_from_bytes(scriptpubkey)
        }

        if self.is_liquid:
            # TODO: also mockup the unblinded case
            amount, asset, a_bl, v_bl, conf = imported[2:]
            generator = wally.asset_generator_from_bytes(
                wally.hex_to_bytes(asset)[::-1],  wally.hex_to_bytes(a_bl)[::-1])
            value_commitment = wally.asset_value_commitment(
                round(float(amount) * 10 ** 8), wally.hex_to_bytes(v_bl)[::-1], generator)
            a_com = wally.hex_from_bytes(generator)
            v_com = wally.hex_from_bytes(value_commitment)
            ret.update({
                "txid": txutil.get_txhash_hex(tx),
                "amount": float(amount),
                "assetcommitment": a_com,
                "asset": asset,
                "amountcommitment": v_com,
                "amountblinder": v_bl,
                "assetblinder": a_bl,
                "confirmations": int(conf),
            })

        return ret

    def listunspent(self, minconf, maxconf, addresses):
        unspent = [self._get_unspent(address) for address in addresses]
        return [x for x in unspent if x]

    def getrawtransaction(self, txid):
        return txutil.to_hex(self.tx_by_id[txid])

    def batch_(self, requests):
        return [getattr(self, call)(params) for call, params in requests]

    def dumpassetlabels(self):
        return {'bitcoin': 'b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23'}

    def getnewaddress(self):
        self.given_addresses += 1
        return mock_addresses[self.given_addresses % len(mock_addresses)]['address']

    def testmempoolaccept(self, tx_list):
        assert isinstance(tx_list, list) and len(tx_list) == 1
        tx = self.tx_from_hex(tx_list[0])
        return [{'txid': txutil.get_txhash_hex(tx), 'allowed': True}]

    def createrawtransaction(self, inputs, map_amount, nlocktime, is_replaceable, map_asset):
        tx = wally.tx_init(wally.WALLY_TX_VERSION_2, nlocktime, len(inputs), len(map_amount))
        sequence = gaconstants.MAX_BIP125_RBF_SEQUENCE
        if not is_replaceable:
            sequence += 1

        for _input in inputs:
            txid = wally.hex_to_bytes(_input['txid'])[::-1]
            wally.tx_add_elements_raw_input(tx, txid, _input['vout'], sequence, None,
                                            None, None, None, None, None, None, None, None, 0)

        fee_value = None
        for address, amount in map_amount.items():
            value = wally.tx_confidential_value_from_satoshi(round(amount * 10 ** 8))
            if address == 'fee':
                fee_value = value
            else:
                mock_address = [e for e in mock_addresses if e['address'] == address][0]
                scriptpubkey = wally.hex_to_bytes(mock_address['scriptpubkey'])
                blindingpubkey = wally.hex_to_bytes(mock_address['public_blinding_key'])
                asset = b'\x01' + wally.hex_to_bytes(map_asset[address])[::-1]
                wally.tx_add_elements_raw_output(
                    tx, scriptpubkey, asset, value, blindingpubkey, None, None, 0)
        # force fee to be the last output, to make things simpler
        lbtc = b'\x01' + wally.hex_to_bytes(self.lbtc_hex)[::-1]
        wally.tx_add_elements_raw_output(tx, None, lbtc, fee_value, None, None, None, 0)

        return self.tx_to_hex(tx)

    def rawblindrawtransaction(
            self, tx_hex, input_vbfs_hex, input_values, input_assets_hex, input_abfs_hex):
        tx = self.tx_from_hex(tx_hex)

        input_values = [round(i * 10 ** 8) for i in input_values]
        input_assets = [wally.hex_to_bytes(h)[::-1] for h in input_assets_hex]
        input_abfs = [wally.hex_to_bytes(h)[::-1] for h in input_abfs_hex]
        input_vbfs = [wally.hex_to_bytes(h)[::-1] for h in input_vbfs_hex]
        input_ags = [
            wally.asset_generator_from_bytes(a, bf) for a, bf in zip(input_assets, input_abfs)]

        input_assets_concat = b''.join(input_assets)
        input_abfs_concat = b''.join(input_abfs)
        input_ags_concat = b''.join(input_ags)

        fake_random_bytes = b'\x77' * 32
        # ephemeral keypair
        fake_eph_key_prv = b'\x00' * 31 + b'\x01'
        fake_eph_key_pub = wally.ec_public_key_from_private_key(fake_eph_key_prv)

        min_value = 1
        ct_exp = 0
        ct_bits = 36

        out_num = wally.tx_get_num_outputs(tx)
        output_blinded_values = []
        for out_idx in range(out_num):
            if wally.tx_get_output_script(tx, out_idx):
                value_bytes = wally.tx_get_output_value(tx, out_idx)
                value_satoshi = wally.tx_confidential_value_to_satoshi(value_bytes)
                output_blinded_values.append(value_satoshi)
            else:
                # fee, make sure it is the last output, to simplify things
                assert out_idx == out_num - 1

        output_abfs = [fake_random_bytes for i in range(out_num - 1)]
        output_vbfs = [fake_random_bytes for i in range(out_num - 2)]
        output_vbfs.append(wally.asset_final_vbf(
            input_values + output_blinded_values, wally.tx_get_num_inputs(tx),
            b''.join(input_abfs + output_abfs), b''.join(input_vbfs + output_vbfs)))

        for out_idx in range(out_num - 1):
            # To be accurate, if an output can't be blinded, we should not set
            # the *proof and set nonce empty, however it is not strictly
            # necessary to mimic the exact behavior in the mockup.
            asset_prefixed = wally.tx_get_output_asset(tx, out_idx)
            value_bytes = wally.tx_get_output_value(tx, out_idx)
            blinding_pubkey = wally.tx_get_output_nonce(tx, out_idx)
            scriptpubkey = wally.tx_get_output_script(tx, out_idx)
            assert scriptpubkey

            assert asset_prefixed[0] == 1 and value_bytes[0] == 1
            value_satoshi = wally.tx_confidential_value_to_satoshi(value_bytes)
            asset = asset_prefixed[1:]

            blinding_nonce = wally.sha256(wally.ecdh(blinding_pubkey, fake_eph_key_prv))

            output_abf = output_abfs[out_idx]
            output_vbf = output_vbfs[out_idx]
            output_generator = wally.asset_generator_from_bytes(asset, output_abf)
            output_value_commitment = wally.asset_value_commitment(
                value_satoshi, output_vbf, output_generator)

            rangeproof = wally.asset_rangeproof_with_nonce(
                value_satoshi, blinding_nonce, asset, output_abf, output_vbf,
                output_value_commitment, scriptpubkey, output_generator, min_value,
                ct_exp, ct_bits)

            surjectionproof = wally.asset_surjectionproof(
                asset, output_abf, output_generator, fake_random_bytes,
                input_assets_concat, input_abfs_concat, input_ags_concat)

            wally.tx_set_output_asset(tx, out_idx, output_generator)
            wally.tx_set_output_value(tx, out_idx, output_value_commitment)
            wally.tx_set_output_nonce(tx, out_idx, fake_eph_key_pub)
            wally.tx_set_output_surjectionproof(tx, out_idx, surjectionproof)
            wally.tx_set_output_rangeproof(tx, out_idx, rangeproof)

        return self.tx_to_hex(tx)

    estimatesmartfee = mock.Mock()
    getblockcount = mock.Mock()
    getnetworkinfo = mock.Mock()
