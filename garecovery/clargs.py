import argcomplete
import argparse
import logging
import os
import sys

from gaservices.utils import gaconstants


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


SUBACCOUNT_TYPES = {
    False: ['2of2', '2of3', '2of2-csv'],
    True: ['csv'],
}


args = None


def set_args(argv, is_liquid=False):
    global args
    args = get_args(argv, is_liquid)


def get_args(argv, is_liquid=False):
    parser = argparse.ArgumentParser(
        description="GreenAddress command line recovery tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument(
        'recovery_mode',
        choices=SUBACCOUNT_TYPES[is_liquid],
        default=SUBACCOUNT_TYPES[is_liquid][0],
        help='Type of recovery to perform')
    parser.add_argument(
        '-n', '--network',
        dest='network',
        choices=gaconstants.SUPPORTED_NETWORKS[is_liquid],
        default=gaconstants.SUPPORTED_NETWORKS[is_liquid][0],
        help="Network the coins belong to")
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

    rpc = parser.add_argument_group(
        ('Elements' if is_liquid else 'Bitcoin') + ' RPC options')

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
        '--rpcwallet',
        dest='rpcwallet'),
    rpc.add_argument(
        '--config-filename',
        dest='config_filename')
    rpc.add_argument(
        '--rpc-timeout-minutes',
        default=60,
        type=int,
        help='Timeout in minutes for rpc calls')

    kwargs_option_search_subaccounts = {
        'dest': 'search_subaccounts',
        'nargs': '?',
        'const': DEFAULT_SUBACCOUNT_SEARCH_DEPTH,
        'type': int,
        'help': 'Number of subaccounts to search for',
    }
    kwargs_option_key_search_depth = {
        'dest': 'key_search_depth',
        'type': int,
        'default': DEFAULT_KEY_SEARCH_DEPTH,
        'help': 'When scanning for transactions search this number of keys',
    }
    kwargs_option_scan_from = {
        'dest': 'scan_from',
        'type': int,
        'default': DEFAULT_SCAN_FROM,
        'help': 'Start scanning the blockchain for transactions from this timestamp. '
                'Scanning the blockchain is slow so if you know your transactions were all after '
                'a certain date you can speed it up by restricting the search range with this '
                'option. Defaults to the inception time of GreenAddress. Pass 0 to scan the entire '
                'blockchain.',
    }

    if is_liquid:
        csv = parser.add_argument_group('CSV options')
        csv.add_argument('--search-subaccounts', **kwargs_option_search_subaccounts)

        advanced_csv = parser.add_argument_group('CSV advanced options')
        advanced_csv.add_argument('--key-search-depth', **kwargs_option_key_search_depth)
        advanced_csv.add_argument('--scan-from', **kwargs_option_scan_from)
        advanced_csv.add_argument(
            '--split-unblinded-inputs',
            dest='split_unblinded_inputs',
            action='store_true',
            help='If any unblinded input is found, split the inputs in two transactions, '
                 'one with blinded inputs and the other with the remaining. '
                 'Note that, if one of the two sets does not contain enough l-btc for the fees, '
                 'the tool may not be able to create the transaction.')
    else:
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

        kwargs_option_search_subaccounts['help'] += \
            '; if --ga-xpub is not known it is possible to search subaccounts using this option'
        action_subaccounts = two_of_three_xpub_exclusive.add_argument(
            '--search-subaccounts', **kwargs_option_search_subaccounts)

        two_of_three_backup_key_exclusive = two_of_three.add_mutually_exclusive_group(
            required=False)
        two_of_three_backup_key_exclusive.add_argument(
            '--recovery-mnemonic-file',
            dest='recovery_mnemonic_file',
            help="Name of file containing the user's recovery mnemonic (2 of 3)")
        two_of_three_backup_key_exclusive.add_argument(
            '--custom-xprv',
            help='Custom xprv (extended private key) for the 2of3 account. '
                 'Only required if an xpub was specified when creating the subaccount')

        advanced_2of3 = parser.add_argument_group('2of3 advanced options')
        action_key = advanced_2of3.add_argument(
            '--key-search-depth', **kwargs_option_key_search_depth)
        action_scan = advanced_2of3.add_argument('--scan-from', **kwargs_option_scan_from)
        action_fee_blocks = advanced_2of3.add_argument(
            '--fee-estimate-blocks',
            dest='fee_estimate_blocks',
            type=int,
            default=DEFAULT_FEE_ESTIMATE_BLOCKS,
            help='Use a transaction fee likely to result in a transaction being '
                 'confirmed in this many blocks minimum')
        action_default_feerate = advanced_2of3.add_argument(
            '--default-feerate',
            dest='default_feerate',
            type=int,
            help='Fee rate (satoshis per byte) to use if unable to automatically get one')

        action_scantxoutset = advanced_2of3.add_argument(
            '--ignore-mempool',
            dest='ignore_mempool',
            action='store_true',
            help='Ignore the mempool when scanning the UTXO set for 2of3 transactions. '
                 'This enables the use of scantxoutset which makes recovery much faster.')

        two_of_two_csv = parser.add_argument_group('2of2 csv options')

        two_of_two_csv._group_actions = [
            action_subaccounts,
            action_key,
            action_scan,
            action_fee_blocks,
            action_default_feerate,
            action_scantxoutset,
        ]

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

    if is_liquid:
        return result

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
    else:
        for arg in ['--destination-address', '--ga-xpub', '--recovery-mnemonic-file',
                    '--custom-xprv', '--nlocktime-file']:
            arg_disallowed(arg)

    return result
