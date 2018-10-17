#!/usr/bin/env python

import mock

import garecovery.two_of_three
from garecovery.clargs import DEFAULT_SUBACCOUNT_SEARCH_DEPTH
from .util import AuthServiceProxy, datafile, get_argparse_error, get_output, raise_IOError


garecovery.bitcoin_config.open = raise_IOError
sub_depth = DEFAULT_SUBACCOUNT_SEARCH_DEPTH
key_depth = 20
destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'
custom_xprv = 'tprv8ZgxMBicQKsPcuswzN4iZ7jhs3mghK6JUDXJvQM4wQac7cGvtSFpx24uF'\
              'Chjvs2DDi6ZqGXjmwXHwWBcZtVMeMGKzqDSbxczJDZRepXNQfo'


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_custom_xprv(mock_bitcoincore):
    """Test --custom-xprv option"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')

    estimate = {'blocks': 3, 'feerate': 1, }
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_8.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--network=testnet',
        '--custom-xprv={}'.format(custom_xprv),
        '--key-search-depth={}'.format(key_depth),
        '--search-subaccounts={}'.format(sub_depth),
        '--destination-address={}'.format(destination_address),
    ]

    signed_tx = get_output(args).strip()
    assert len(signed_tx) > 0


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_custom_xprv_recovery_mnemonic(mock_bitcoincore):
    """Test --custom-xprv and --recovery-mnemonic-file options are mutually exclusive"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')
    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_8.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--network=testnet',
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_10.txt')),
        '--custom-xprv={}'.format(custom_xprv),
        '--key-search-depth={}'.format(key_depth),
        '--search-subaccounts={}'.format(sub_depth),
        '--destination-address={}'.format(destination_address),
    ]

    output = get_argparse_error(args)
    assert '--custom-xprv: not allowed with argument --recovery-mnemonic-file' in output
