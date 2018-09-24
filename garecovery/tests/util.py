import csv
import mock
import os
import sys
import unittest

try:
    # Python 2
    import StringIO as io
    import exceptions as exc
except ImportError:
    # Python 3
    import io
    import builtins as exc

from garecovery.recoverycli import main
from garecovery import clargs
from gaservices.utils import txutil
import wallycore as wally


TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), 'test_data')


def datafile(filename):
    return os.path.join(TEST_DATA_DIR, filename)


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


def get_output_ex(args, expect_error=False):
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
            result = main([sys.argv[0], ] + args)
            if expect_error:
                assert result != 0, output.getvalue()
            else:
                assert result == 0, output.getvalue()

        # Convert StringIOs in ofiles to string content for convenience
        ofiles = {filename: ofiles[filename].getvalue() for filename in ofiles}
        return output.getvalue(), ofiles


def get_output(args, expect_error=False):
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

    output, ofiles = get_output_ex(filtered_args, expect_error)

    if expect_error:
        return output

    if show_summary:
        # the summary view is backward compatible automatically
        return output
    else:
        # In legacy mode if you did not pass --show-summary you got raw output depending on the
        # recovery mode. Can use the csv output to reconstruct it
        csv_content = ofiles[clargs.DEFAULT_OFILE]
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
