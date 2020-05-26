#!/usr/bin/env python3

import decimal
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


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_recover_2of2_csv(mock_bitcoincore):
    """Test 2of2-csv happy path"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')

    estimate = {'blocks': 3, 'feerate': decimal.Decimal('0.00001'), }
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate
    mock_bitcoincore.return_value.getnetworkinfo = mock.Mock(return_value={'version': 190100})
    mock_bitcoincore.return_value.getblockcount.return_value = 144

    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_1.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of2-csv',
        '--network=testnet',
        '--key-search-depth={}'.format(key_depth),
        '--search-subaccounts={}'.format(sub_depth),
    ]

    # Raw tx
    output = get_output(args).strip()
    assert output == open(datafile("signed_2of2_csv_1")).read().strip()

    tx = txutil.from_hex(output)
    assert wally.tx_get_num_inputs(tx) == 1

    # Summary
    args = ['--show-summary', ] + args
    output = get_output(args)
    summary = parse_summary(output)
    assert len(summary) == 1

    # Use scantxoutset instead of importmulti + listunspent
    scantxoutset_result = {
        'success': True,
        'unspents': [{
            'txid': '0ab5d70ef25a601de455155fdcb8c492d21a9b3063211dc8a969568d9d0fe15b',
            'vout': 0,
            'scriptPubKey': 'a91458ce12e1773dd078940a9dc855b94c3c9a343b8587',
            'desc': 'addr(2N1LnKRLTCWr8H9UdwoREazuFDXHMEgZj9g)#ztm9gzsm',
            'amount': 0.001,
            'height': 0,
        }],
    }
    mock_bitcoincore.return_value.scantxoutset = mock.Mock(return_value=scantxoutset_result)
    # output not expired yet
    mock_bitcoincore.return_value.getblockcount.return_value = 143

    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_1.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of2-csv',
        '--network=testnet',
        '--key-search-depth={}'.format(key_depth),
        '--search-subaccounts={}'.format(sub_depth),
        '--ignore-mempool',
    ]

    # Raw tx
    raw_tx = get_output(args).strip()
    assert raw_tx == ''

    # output expired
    mock_bitcoincore.return_value.getblockcount.return_value = 144

    # Raw tx
    output = get_output(args).strip()
    assert output == open(datafile("signed_2of2_csv_1")).read().strip()

    # Check replace by fee is set
    tx = txutil.from_hex(output)
    assert wally.tx_get_num_inputs(tx) == 1

    # Summary
    args = ['--show-summary', ] + args
    output = get_output(args)
    summary = parse_summary(output)
    assert len(summary) == 1
