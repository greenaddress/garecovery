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
    two_of_three = False
    show_summary = False
    for arg in args:
        if arg in ['--show-summary', '-s']:
            show_summary = True
        else:
            if arg == '2of3':
                two_of_three = True
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
        if two_of_three:
            # simply the raw transactions
            lines = [row['raw tx'] for row in csv_]
            return '\n'.join(lines)
        else:
            # in 2of2 you got the raw tx but also the private key
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

    def __init__(self, txfile):
        self.tx_by_id = {}
        self.txout_by_address = {}
        for line in open(datafile(txfile)).readlines():
            tx = txutil.from_hex(line.strip())
            self.tx_by_id[txutil.get_txhash_bin(tx)] = tx
            for i in range(wally.tx_get_num_outputs(tx)):
                addr = txutil.get_output_address(tx, i, gaconstants.ADDR_VERSIONS_TESTNET,
                                                 gaconstants.ADDR_FAMILY_TESTNET)
                self.txout_by_address[addr] = (tx, i)
        self.imported = {}

        # This is something of a workaround because all the existing tests are based on generating
        # txs where nlocktime was fixed as 0. The code changed to use current blockheight, so by
        # fudging this value to 0 the existing tests don't notice the difference
        self.getblockcount.return_value = 0

        self.getnetworkinfo.return_value = {'version': 160000}

    def importmulti(self, requests):
        result = []
        for request in requests:
            assert request['watchonly'] is True
            address = request['scriptPubKey']['address']
            if address in self.txout_by_address:
                self.imported[address] = self.txout_by_address[address]
            result.append({'success': True})
        return result

    def _get_unspent(self, address):
        imported = self.imported.get(address, None)
        if imported is None:
            return None
        tx, i = imported
        script = wally.tx_get_output_script(tx, i)
        return {
            "txid": txutil.get_txhash_bin(tx),
            "vout": i,
            "address": address,
            "scriptPubKey": wally.hex_from_bytes(script)
        }

    def listunspent(self, minconf, maxconf, addresses):
        unspent = [self._get_unspent(address) for address in addresses]
        return [x for x in unspent if x]

    def getrawtransaction(self, txid):
        return txutil.to_hex(self.tx_by_id[txid])

    def batch_(self, requests):
        return [getattr(self, call)(params) for call, params in requests]

    estimatesmartfee = mock.Mock()
    getblockcount = mock.Mock()
    getnewaddress = mock.Mock()
    getnetworkinfo = mock.Mock()
