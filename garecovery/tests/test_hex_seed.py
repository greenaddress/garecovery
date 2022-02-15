#!/usr/bin/env python3

import mock

import garecovery

from .util import AuthServiceProxy, datafile, get_output, parse_summary, raise_IOError


garecovery.bitcoin_config.open = raise_IOError
sub_depth = garecovery.clargs.DEFAULT_SUBACCOUNT_SEARCH_DEPTH
key_depth = 20
destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'
xpub = 'tpubEDNQxNxDqhj7Qoyv7ELkQShpL1qdFWePuTnVzX4civm9Tt7an3MLVXfr'\
       'v7VNA29HCLejMoLK8oLkGV5mupFt7LhWQ4CCRYXoMcfvx3dDJs4'


@mock.patch('garecovery.bitcoincore.AuthServiceProxy', None)
def test_hex_seed_login():
    """Test that it's possible to use a hex seed rather than mnemonic"""
    output = get_output([
        '--mnemonic-file={}'.format(datafile('hex_seed_hw_2.txt')),
        '--show-summary',
        '2of2',
        '--network=testnet',
        '--nlocktime-file={}'.format(datafile('nlocktimes_hw_2.zip')),
    ])
    summary = parse_summary(output)
    assert len(summary) == 1
    assert summary[0]['destination address'] == 'n2XzrydLuz1cAdP9m4tRrv98LNVfu9Q5u8'


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_hex_seeds(mock_bitcoincore):
    """Test hex seeds for 2of3"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')

    estimate = {'blocks': 3, 'feerate': 0, }
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    args = [
        '--mnemonic-file={}'.format(datafile('hex_seed_hw_3.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--network=testnet',
        '--recovery-mnemonic-file={}'.format(datafile('hex_seed_hw_4.txt')),
        '--key-search-depth={}'.format(key_depth),
        '--search-subaccounts={}'.format(sub_depth),
        '--destination-address={}'.format(destination_address),
    ]

    assert get_output(args).strip() == open(datafile('signed_2of3_7')).read().strip()


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_hex_seeds_with_xpub(mock_bitcoincore):
    """Test providing hex seeds instead of mnemonics"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')

    estimate = {'blocks': 3, 'feerate': 1, }
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    args = [
        '--mnemonic-file={}'.format(datafile('hex_seed_8.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--network=testnet',
        '--recovery-mnemonic-file={}'.format(datafile('hex_seed_10.txt')),
        '--key-search-depth={}'.format(key_depth),
        '--destination-address={}'.format(destination_address),
        '--ga-xpub={}'.format(xpub),
    ]

    assert get_output(args).strip() == open(datafile('signed_2of3_6')).read().strip()
