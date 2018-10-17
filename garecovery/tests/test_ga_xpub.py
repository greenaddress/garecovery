#!/usr/bin/env python

import mock

import garecovery.bitcoin_config
from garecovery.clargs import DEFAULT_SUBACCOUNT_SEARCH_DEPTH
from .util import AuthServiceProxy, datafile, get_argparse_error, get_output, raise_IOError


garecovery.bitcoin_config.open = raise_IOError
sub_depth = DEFAULT_SUBACCOUNT_SEARCH_DEPTH
key_depth = 20
destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_provide_xpub(mock_bitcoincore):
    """Test --ga-xpub option"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')

    estimate = {'blocks': 3, 'feerate': 1, }
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_8.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--network=testnet',
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_10.txt')),
        '--key-search-depth={}'.format(key_depth),
        '--destination-address={}'.format(destination_address),
    ]

    # If the xpub is not specified the tool can derive it
    arg = '--search-subaccounts={}'.format(sub_depth)
    signed_tx_derived_xpub = get_output(args + [arg, ]).strip()
    assert len(signed_tx_derived_xpub) > 0
    assert signed_tx_derived_xpub == open(datafile('signed_2of3_6')).read().strip()

    # Incorrect but otherwise valid xpub (for a different account)
    # This results in not finding the tx
    incorrect_xpub = 'tpubEDNQxNxDqhj7M1Wn675apdTaZax2bTNvVNWBSnJcyiKLVNXEZErBKC'\
                     'VNmTaxfgwawLkKf8XMj2u72YDvcqzzyLexSp7vfnMiqPHm8bUmop5'
    arg = '--ga-xpub={}'.format(incorrect_xpub)
    assert len(get_output(args + [arg, ])) == 0

    # This xpub matches the derived one
    correct_xpub = 'tpubEDNQxNxDqhj7Qoyv7ELkQShpL1qdFWePuTnVzX4civm9Tt7an3MLVXfr'\
                   'v7VNA29HCLejMoLK8oLkGV5mupFt7LhWQ4CCRYXoMcfvx3dDJs4'
    arg = '--ga-xpub={}'.format(correct_xpub)
    assert get_output(args + [arg, ]).strip() == signed_tx_derived_xpub


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_xpub_and_subaccount_search(mock_bitcoincore):
    """Test that the options --ga-xpub and --search-subaccounts are mutually exlcusive"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')
    estimate = {'blocks': 3, 'feerate': 1, }
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate
    xpub = 'tpubEDNQxNxDqhj7Qoyv7ELkQShpL1qdFWePuTnVzX4civm9Tt7an3MLVXfr'\
           'v7VNA29HCLejMoLK8oLkGV5mupFt7LhWQ4CCRYXoMcfvx3dDJs4'
    args = [
        '--mnemonic-file={}'.format(datafile('hex_seed_8.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--network=testnet',
        '--recovery-mnemonic-file={}'.format(datafile('hex_seed_10.txt')),
        '--key-search-depth={}'.format(key_depth),
        '--destination-address={}'.format(destination_address),
        '--search-subaccounts',
        '--ga-xpub={}'.format(xpub),
    ]

    output = get_argparse_error(args)
    assert '--ga-xpub: not allowed with argument --search-subaccounts' in output
