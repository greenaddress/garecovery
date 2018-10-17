#!/usr/bin/env python

import mock

import garecovery.two_of_three
from garecovery.clargs import DEFAULT_SUBACCOUNT_SEARCH_DEPTH
from .util import AuthServiceProxy, datafile, get_output, raise_IOError


garecovery.bitcoin_config.open = raise_IOError
sub_depth = DEFAULT_SUBACCOUNT_SEARCH_DEPTH
key_depth = 20
default_feerate = 330
destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_scan_blockchain(mock_bitcoincore):
    """Test scanning the blockchain via mocked core"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')

    estimate = {'blocks': 3, 'feerate': -1, }
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    # Return a fake fixed unspent which happens to match the scriptPubKey
    # corresponding to the fifth keyset
    mock_bitcoincore.return_value.listunspent = mock.Mock()
    mock_bitcoincore.return_value.listunspent.return_value = [
        {
            'scriptPubKey': 'a9145100774c0ed205038fa07aeff0eb293c17b650f087',
            'txid': 'fake_tx_id',
            'vout': 0,
        },
    ]

    # Return a fixed raw tx
    mock_bitcoincore.return_value.getrawtransaction = mock.Mock()
    raw_tx = open(datafile('raw_2of3_tx_1')).read().strip()
    mock_bitcoincore.return_value.getrawtransaction.return_value = raw_tx

    def getargs(key_search_depth):

        return [
            '--mnemonic-file={}'.format(datafile('mnemonic_2.txt')),
            '--rpcuser=abc',
            '--rpcpassword=abc',
            '2of3',
            '--network=testnet',
            '--recovery-mnemonic-file={}'.format(datafile('mnemonic_3.txt')),
            '--key-search-depth={}'.format(key_search_depth),
            '--search-subaccounts={}'.format(sub_depth),
            '--destination-address={}'.format(destination_address),
            '--default-feerate={}'.format(default_feerate),
        ]

    # Key depth five matches one tx
    output = get_output(getargs(key_search_depth=5))
    assert output.strip() == open(datafile("signed_2of3_3")).read().strip()

    mock_bitcoincore.return_value.getrawtransaction.assert_called_once_with('fake_tx_id')

    # If key search depth is only four the transaction will not be found
    output = get_output(getargs(key_search_depth=4))
    assert output == ""

    # Add another matching unspent matching the first keyset
    mock_bitcoincore.return_value.listunspent.return_value.append({
        'scriptPubKey': 'a9143e8ae1d483d5fa0b20d917f32517191eeb64034287',
        'txid': 'fake_tx_id_2',
        'vout': 0,
    })

    # Scan on key depth five finds both transactions
    output = get_output(getargs(key_search_depth=5))
    txs = output.split()
    assert len(txs) == 2

    mock_bitcoincore.return_value.getrawtransaction.assert_has_calls([
        mock.call('fake_tx_id'),
        mock.call('fake_tx_id_2'),
    ])

    # Scan with key depth four also finds both txs because the initial
    # scan up to 4 finds one, which triggers a subsequent scan which finds
    # the second
    output = get_output(getargs(key_search_depth=4))
    txs = output.split()
    assert len(txs) == 2
    assert txs[0] == open(datafile("signed_2of3_4")).read().strip()
    assert txs[1] == open(datafile("signed_2of3_3")).read().strip()

    # Scan using scantxoutset
    mock_bitcoincore.return_value.getnetworkinfo = mock.Mock(return_value={'version': 170000})
    mock_bitcoincore.return_value.scantxoutset = mock.Mock(return_value={
        'unspents': [{
            'txid': 'fake_tx_id',
            'vout': 0,
            'scriptPubKey': 'a9145100774c0ed205038fa07aeff0eb293c17b650f087',
            'amount': 0,
            'height': 0,
        }],
        'total_amount': 0
    })

    # Key depth five matches one tx
    output = get_output(getargs(key_search_depth=5) + ['--ignore-mempool'])
    assert output.strip() == open(datafile("signed_2of3_3")).read().strip()

    mock_bitcoincore.return_value.getnetworkinfo = mock.Mock(return_value={'version': 160000})
    output = get_output(getargs(key_search_depth=5) + ['--ignore-mempool'], expect_error=True)
    assert '--ignore-mempool cannot be specified if you run an old version' in output
