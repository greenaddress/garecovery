"""Formatting operations for output of transactions"""
import collections
import sys
import wallycore as wally
from gaservices.utils import txutil

from . import clargs
from . import util


def btc(amount_satoshis, units='BTC'):
    """Given an amount in satoshis return a display string"""
    divisor = {
        'BTC': 1e8,
        'mBTC': 1e5,
        'uBTC': 1e2,
        'bit': 1e2,
        'sat': 1}[units]
    amount = amount_satoshis/divisor
    spec = units
    if spec == 'bit' and amount != 1:
        spec = 'bits'
    return '{} {}'.format(amount, spec)


def unitify(quantity, unit):
    """Format an amount with units specifier handling options plural 's'"""
    return '{} {}'.format(quantity, unit if quantity == 1 else unit + 's')


def get_time_remaining_string(current_blockcount, lock_time):
    """Return a string indicating the time to go before tx can be spent

    e.g.
    100 (12 blocks/~120 minutes to go)
    """
    assert lock_time > current_blockcount
    # TODO: does not handle datetime encoded into locktime
    remaining_blocks = lock_time - current_blockcount
    MINS_PER_BLOCK = 10
    quantity = remaining_blocks * MINS_PER_BLOCK
    for unit_, divisor in [('minute', 60), ('hour', 24), ('day', None)]:
        if divisor is None or quantity < divisor:
            unit = unit_
            break
        else:
            quantity //= divisor

    remaining = unitify(remaining_blocks, 'block')
    quantity = unitify(quantity, unit)
    return '{} ({}/~{} to go)'.format(lock_time, remaining, quantity)


def format_nlocktime_string(current_blockcount, lock_time):
    """Return a display string showing the nlocktime and how long to go"""
    if current_blockcount:
        if lock_time > current_blockcount:
            return get_time_remaining_string(current_blockcount, lock_time)
        else:
            return '{} *spendable now'.format(lock_time)
    else:
        # current block count unknown
        return '{}'.format(lock_time)


Column = collections.namedtuple('Column', ['heading', 'value'])


class Formatter:

    def __init__(self, txs):
        # This is a bit of a hack to handle the fact that txs may or may not have private_key
        # attributes and the output needs to handle that dynamically
        self.has_private_keys = len(txs) and txs[0][0] is not None

        self.units = clargs.args.units
        self.current_blockcount = util.get_current_blockcount()
        self.column_defs = self.get_column_defs(self.units, self.current_blockcount)
        self.columns = [[column_def.heading, ] for column_def in self.column_defs]
        self.total, self.total_utxos = self.append_column_data(txs, self.columns, self.column_defs)

    def append_column_data(self, txs, columns, summary_columns):
        """Iterate through utxos appending column data to column for each

        Return total in BTC and total number of utxos
        """
        total = 0
        total_utxos = 0
        for tx_wif in txs:
            for idx in range(wally.tx_get_num_outputs(tx_wif[0])):
                values = [column.value(tx_wif, idx) for column in summary_columns]
                for i, value in enumerate(values):
                    columns[i].append(value)
                total += wally.tx_get_output_satoshi(tx_wif[0], idx)
                total_utxos += 1
        return total, total_utxos

    def format_columns(self, columns, format_string, underlines=None):
        """Yield lines of formatted data"""
        def format_(row):
            return format_string.format(*row)

        rows = list(zip(*columns))
        rows = [format_(row) for row in rows]
        headings = rows[0]

        yield headings
        if underlines:
            yield format_(underlines)
        for row in rows[1:]:
            yield row


class SummaryFormatter(Formatter):

    def __init__(self, txs):
        Formatter.__init__(self, txs)

        # Define format string with fixed widths for each column
        lengths = [[len(datum) for datum in column] for column in self.columns]
        column_widths = [max(length) for length in lengths]
        formatters = ["{{: >{}}}".format(width) for width in column_widths]
        self.format_string = ' '.join(formatters)

        # Summary has a row which underlines the headings
        underline_headings_char = '-'
        self.underlines = [underline_headings_char * width for width in column_widths]

    def get_column_defs(self, units, current_blockcount):

        def get_nlocktime(tx_wif, _):
            return format_nlocktime_string(current_blockcount, wally.tx_get_locktime(tx_wif[0]))

        def get_coin_value(tx_wif, idx):
            return btc(wally.tx_get_output_satoshi(tx_wif[0], idx), units)

        def get_bitcoin_address(tx_wif, idx):
            addr_versions = [b'\x6f', b'\xc4'] if clargs.args.is_testnet else [b'\x00', b'\x05']
            return txutil.get_output_address(tx_wif[0], idx, addr_versions)

        # A list of (heading, fn) for each column in the summary where fn is a function that takes
        # (tx, txout index) and returns a value for the column
        columns = [
            ('tx id', lambda tx_wif, _: txutil.get_txhash_hex(tx_wif[0])),
            ('lock time', get_nlocktime),
            ('total out', lambda tx_wif, _: btc(txutil.total_output_satoshi(tx_wif[0]), units)),
            ('destination address', get_bitcoin_address),
            ('coin value', get_coin_value)
        ]
        return [Column(heading, fn) for heading, fn in columns]

    def format(self, columns):
        """Yield lines of text for the output according to formatting rules"""
        for line in self.format_columns(columns, self.format_string, self.underlines):
            yield line

    def write_txs(self, out):
        for line in self.format(self.columns):
            out.write("{}\n".format(line))

    def write_totals(self, out):
        out.write("\ntotal value = {} in {}\n".format(
            btc(self.total, self.units),
            self.total_utxos,
            unitify(self.total_utxos, 'utxo')))

    def write(self, out):
        self.write_txs(out)
        self.write_totals(out)


class CsvFormatter(SummaryFormatter):

    def __init__(self, txs):
        Formatter.__init__(self, txs)

        self.format_string = ','.join(['{}' for column in self.columns])
        self.underlines = None

    @staticmethod
    def get_raw_tx_column():
        """Return raw tx column

        Contains either the raw transaction in hex or a string indicating dust output. Transactions
        where value is <= 0 are shown as dust.
        """
        def get_raw_tx_or_dust(tx_wif, _):
            if txutil.total_output_satoshi(tx_wif[0]) == 0:
                return '** dust **'
            return txutil.to_hex(tx_wif[0])
        return Column('raw tx', get_raw_tx_or_dust)

    @staticmethod
    def get_private_keys_column():
        return Column('private key', lambda tx_wif, _: tx_wif[1])

    def get_column_defs(self, units, current_blockcount):
        defs = SummaryFormatter.get_column_defs(self, units, current_blockcount)
        defs.append(self.get_raw_tx_column())
        if self.has_private_keys:
            defs.append(self.get_private_keys_column())
        return defs

    def write_totals(self, out):
        # CSV does not write totals
        pass


def write_summary(txs, ofile):
    SummaryFormatter(txs).write(ofile)


def write_csv(txs, ofile):
    CsvFormatter(txs).write(ofile)
