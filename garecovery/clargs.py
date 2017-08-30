import argcomplete
import argparse
import logging
import os
import sys


# Define GreenAddress_T0 as the earliest possible GreenAddress UTXO
# This is used as the default value for scanning the blockchain
# 28 Feb 2014
GreenAddress_T0 = 1393545600

# Some defaults here make it easier for tests to override them
DEFAULT_SCAN_FROM = GreenAddress_T0
DEFAULT_KEY_SEARCH_DEPTH = 10000
DEFAULT_SUBACCOUNT_SEARCH_DEPTH = 10
DEFAULT_FEE_ESTIMATE_BLOCKS = 6
DEFAULT_OFILE = 'garecovery.csv'


def default_tx_cache_filename():
    return os.path.expanduser('~/.garecovery_txcache')


args = None


def set_args(argv):
    global args
    args = get_args(argv)


def get_args(argv):
    parser = argparse.ArgumentParser(
        description="GreenAddress command line recovery tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument(
        'recovery_mode',
        choices=['2of2', '2of3'],
        default='2of2',
        help='Type of recovery to perform')
    parser.add_argument(
        '--mnemonic-file',
        dest='mnemonic_file',
        help="Name of file containing the user's mnemonic")
    parser.add_argument(
        '-o', '--output-file',
        default=DEFAULT_OFILE,
        help='Output file for csv data')
    parser.add_argument(
        '-s', '--show-summary',
        dest='show_summary',
        action='store_true',
        help='Show a summary of the transactions available to recover')
    parser.add_argument(
        '--units',
        choices=['BTC', 'mBTC', 'uBTC', 'bit', 'sat'],
        default='BTC',
        dest='units',
        help='Units to display amounts')
    parser.add_argument(
        '--current-blockcount',
        dest='current_blockcount',
        type=int,
        help='Specify the current blockchain height')
    parser.add_argument(
        '-d', '-vv', '--debug',
        help="Print lots of debugging statements",
        action="store_const", dest="loglevel", const=logging.DEBUG,
        default=logging.WARNING)
    parser.add_argument(
        '-v', '--verbose',
        help="Be verbose",
        action="store_const", dest="loglevel", const=logging.INFO)

    rpc = parser.add_argument_group('Bitcoin RPC options')

    rpc.add_argument(
        '--rpcuser',
        dest='rpcuser')
    rpc.add_argument(
        '--rpcpassword',
        dest='rpcpassword')
    rpc.add_argument(
        '--rpccookiefile',
        dest='rpccookiefile')
    rpc.add_argument(
        '--rpcconnect',
        dest='rpcconnect',
        default='127.0.0.1')
    rpc.add_argument(
        '--rpcport',
        dest='rpcport')
    rpc.add_argument(
        '--config-filename',
        dest='config_filename')
    rpc.add_argument(
        '--rpc-timeout-minutes',
        default=60,
        type=int,
        help='Timeout in minutes for rpc calls')

    two_of_two = parser.add_argument_group('2of2 options')
    two_of_two.add_argument(
        '--nlocktime-file',
        help='Name of the nlocktime file sent from GreenAddress')

    two_of_three = parser.add_argument_group('2of3 options')
    two_of_three.add_argument(
        '--destination-address',
        help='An address to recover 2of3 transactions to')

    two_of_three_xpub_exclusive = two_of_three.add_mutually_exclusive_group(required=False)
    two_of_three_xpub_exclusive.add_argument(
        '--ga-xpub',
        help='The GreenAddress extended public key. If not provided the recovery tool will '
             'attempt to derive it')
    two_of_three_xpub_exclusive.add_argument(
        '--search-subaccounts',
        nargs='?',
        const=DEFAULT_SUBACCOUNT_SEARCH_DEPTH,
        type=int,
        help='If --ga-xpub is not known it is possible to search subaccounts using this option')

    two_of_three_backup_key_exclusive = two_of_three.add_mutually_exclusive_group(required=False)
    two_of_three_backup_key_exclusive.add_argument(
        '--recovery-mnemonic-file',
        dest='recovery_mnemonic_file',
        help="Name of file containing the user's recovery mnemonic (2 of 3)")
    two_of_three_backup_key_exclusive.add_argument(
        '--custom-xprv',
        help='Custom xprv (extended private key) for the 2of3 account. '
             'Only required if an xpub was specified when creating the subaccount')

    basic_2of3 = two_of_three.add_argument_group('Basic options')
    basic_2of3.add_argument(
        '--rescan',
        action='store_true',
        help='Rescan the blockchain (or scan file) looking for available '
             '2 of 3 transactions. Can be slow.')

    advanced_2of3 = two_of_three.add_argument_group('Advanced options')
    advanced_2of3.add_argument(
        '--key-search-depth',
        type=int,
        default=DEFAULT_KEY_SEARCH_DEPTH,
        help='When scanning for 2of3 transactions search this number of keys')
    advanced_2of3.add_argument(
        '--scan-from',
        type=int,
        dest='scan_from',
        default=DEFAULT_SCAN_FROM,
        help='Start scanning the blockchain for transactions from this timestamp. '
             'Scanning the blockchain is slow so if you know your transactions were all after '
             'a certain date you can speed it up by restricting the search range with this '
             'option. Defaults to the inception time of GreenAddress. Pass 0 to scan the entire '
             'blockchain.')
    advanced_2of3.add_argument(
        '--fee-estimate-blocks',
        dest='fee_estimate_blocks',
        type=int,
        default=DEFAULT_FEE_ESTIMATE_BLOCKS,
        help='Use a transaction fee likely to result in a transaction being '
             'confirmed in this many blocks minimum')
    advanced_2of3.add_argument(
        '--default-feerate',
        dest='default_feerate',
        type=int,
        help='Fee rate (satoshis per byte) to use if unable to automatically get one')

    argcomplete.autocomplete(parser)
    result = parser.parse_args(argv[1:])

    def optval(name):
        attrname = name.replace('-', '_').replace('__', '')
        return getattr(result, attrname, None)

    def arg_required(name, display_names=None):
        if optval(name) is None:
            name = name if display_names is None else display_names
            parser.error('%s required for mode %s' % (name, result.recovery_mode))

    def arg_disallowed(name):
        if optval(name) is not None:
            parser.error('%s not allowed for mode %s' % (name, result.recovery_mode))

    if result.recovery_mode == '2of2':
        arg_required('--nlocktime-file')
        for arg in ['--destination-address', '--ga-xpub', '--search-subaccounts',
                    '--recovery-mnemonic-file', '--custom-xprv', '--default-feerate']:
            arg_disallowed(arg)

    elif result.recovery_mode == '2of3':
        arg_disallowed('--nlocktime-file')
        arg_required('--destination-address')
        if optval('search_subaccounts') is None:
            arg_required('--ga-xpub', '--ga-xpub or --search-subaccounts')

    return result
