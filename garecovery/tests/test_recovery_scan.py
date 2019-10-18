#!/usr/bin/env python3

import mock
import wallycore as wally

import garecovery.two_of_three
from garecovery.clargs import DEFAULT_SUBACCOUNT_SEARCH_DEPTH
from gaservices.utils import txutil
from .util import AuthServiceProxy, datafile, get_output, parse_summary, raise_IOError


garecovery.bitcoin_config.open = raise_IOError
sub_depth = DEFAULT_SUBACCOUNT_SEARCH_DEPTH
key_depth = 20
destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_recover_2of3(mock_bitcoincore):
    """Test 2of3 happy path"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')

    estimate = {'blocks': 3, 'feerate': 1, }
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_6.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--network=testnet',
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_7.txt')),
        '--key-search-depth={}'.format(key_depth),
        '--search-subaccounts={}'.format(sub_depth),
        '--destination-address={}'.format(destination_address),
    ]

    # Raw tx
    output = get_output(args).strip()
    assert output == open(datafile("signed_2of3_5")).read().strip()

    # Check replace by fee is set
    tx = txutil.from_hex(output)
    assert wally.tx_get_num_inputs(tx) == 1
    assert wally.tx_get_input_sequence(tx, 0) == int(32*'1', 2) - 2

    # Summary
    args = ['--show-summary', ] + args
    output = get_output(args)
    summary = parse_summary(output)
    assert len(summary) == 1
    assert summary[0]['destination address'] == destination_address


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_set_nlocktime(mock_bitcoincore):
    """Test that newly created recovery transactions have nlocktime = current blockheight + 1"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')
    estimate = {'blocks': 3, 'feerate': 1, }
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    current_blockheight = 123
    mock_bitcoincore.return_value.getblockcount.return_value = current_blockheight

    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_6.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--network=testnet',
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_7.txt')),
        '--key-search-depth={}'.format(key_depth),
        '--search-subaccounts={}'.format(sub_depth),
        '--destination-address={}'.format(destination_address),
    ]

    output = get_output(args).strip()
    tx = txutil.from_hex(output)
    assert wally.tx_get_locktime(tx) == current_blockheight
