#!/usr/bin/env python3

import mock

import garecovery.liquid_recovery
from garecovery.clargs import DEFAULT_SUBACCOUNT_SEARCH_DEPTH
from garecovery.tests.util import AuthServiceProxy, datafile, get_output, parse_summary, \
    raise_IOError, mock_addresses_liquid


garecovery.bitcoin_config.open = raise_IOError
sub_depth = DEFAULT_SUBACCOUNT_SEARCH_DEPTH
key_depth = 20


@mock.patch('garecovery.liquid_recovery.bitcoincore.AuthServiceProxy')
def test_csv(mock_bitcoincore):
    """Test Liquid CSV happy path"""
    mock_bitcoincore.return_value = AuthServiceProxy('liquid_txs', is_liquid=True)
    mock_bitcoincore.return_value.getnetworkinfo = mock.Mock(return_value={'version': 180101})
    scantxoutset_result = {
        'success': True,
        'unspents': [{
            'txid': 'd5a1c060f27c21997179a7eb61a67272450a79aeb6a068c1beabfacfae53fc17',
            'vout': 0,
            'scriptPubKey': 'a914d2924bcb2ddd0874fa87268ca53417ad102e811587',
            'desc': 'addr(XWYe1FwJci5gXvjzK6qBoYi1SfPwporjMz)#25yupueg',
            'amountcommitment':
                '097afc5314ca6352160ab736af7523a236a0f18bcbfe1e79f3e688368b35469a7e',
            'assetcommitment': '0a5f0103e2c5b332ff766d489536fb57fad18e6f10cd23198721a85513489602bb',
            'height': 0,
        }],
    }
    mock_bitcoincore.return_value.scantxoutset = mock.Mock(return_value=scantxoutset_result)
    mock_bitcoincore.return_value.getblockhash = mock.Mock(return_value='00'*32)
    mock_bitcoincore.return_value.getrawtransaction = mock.Mock(
        return_value=open(datafile('raw_tx_1')).read().strip())
    # output not expired yet
    mock_bitcoincore.return_value.getblockcount.return_value = 143

    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_1.txt')),
        'csv',
        '--network=localtest-liquid',
        '--key-search-depth={}'.format(key_depth),
        '--search-subaccounts={}'.format(sub_depth),
    ]

    # Raw tx
    raw_tx = get_output(args, is_liquid=True).strip()
    assert raw_tx == ''

    # output expired
    mock_bitcoincore.return_value.getblockcount.return_value = 144

    # Raw tx
    raw_txs = get_output(args, is_liquid=True).strip().split()
    assert raw_txs[0] == raw_txs[1] == open(datafile("signed_csv_1")).read().strip()

    # Summary
    output = get_output(['--show-summary', ] + args, is_liquid=True)
    summary = parse_summary(output)
    assert len(summary) == 2
    assert summary[0]['destination address'] == mock_addresses_liquid[0]['unconfidential_address']


@mock.patch('garecovery.liquid_recovery.bitcoincore.AuthServiceProxy')
def test_asset_csv(mock_bitcoincore):
    """Test Liquid asset recovery"""
    mock_bitcoincore.return_value = AuthServiceProxy('liquid_txs', is_liquid=True)
    mock_bitcoincore.return_value.getnetworkinfo = mock.Mock(return_value={'version': 180101})
    scantxoutset_result = {
        'success': True,
        'unspents': [{
            'txid': '28687bea99bea46fcdf04c5ac2d61e20a50a8baec146dd138718b1fcdfb84ec3',
            'vout': 2,
            'scriptPubKey': 'a914fdbd477728bb5d9a7e9f91ae429817584a9f9e0c87',
            'desc': 'addr(XaUtZ2PMPTcKnVLHuRwp5REzTwyzjFLjix)#25yupueg',
            'amountcommitment':
                '08dd32cab0d056442bdb3fa0dffc470abf4bc169a50d1312cc6ee721a7298cd0d3',
            'assetcommitment': '0a05d405a85dcd6e18f43ff27f03cc0dc966e5695aaf88d5005ee25df4b4c6157f',
            'height': 0,
        }, {
            'txid': '28687bea99bea46fcdf04c5ac2d61e20a50a8baec146dd138718b1fcdfb84ec3',
            'vout': 0,
            'scriptPubKey': 'a91444aae2eeb5f562e0c7d49275e2f8d8355e2b9c9f87',
            'desc': 'addr(XHcKWb5ap9kani16sRx5C6mkWFxnmNyxAZ)#25yupueg',
            'amountcommitment':
                '08fcebb24b4b79ae24c46aded9848f1e04eb6343f8c2fdacbf8f9005d0634e1665',
            'assetcommitment': '0bba366e88398a23eac2a78fc74945316650d874f9966885dde8c787dfec4ba13a',
            'height': 0,
        }],
    }
    mock_bitcoincore.return_value.scantxoutset = mock.Mock(return_value=scantxoutset_result)
    mock_bitcoincore.return_value.getblockhash = mock.Mock(return_value='00'*32)
    mock_bitcoincore.return_value.getrawtransaction = mock.Mock(
        return_value=open(datafile('raw_tx_2')).read().strip())
    mock_bitcoincore.return_value.getblockcount.return_value = 144

    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_2.txt')),
        'csv',
        '--network=localtest-liquid',
        '--key-search-depth={}'.format(key_depth),
        '--search-subaccounts={}'.format(sub_depth),
    ]

    # Raw tx
    raw_txs = get_output(args, is_liquid=True).strip().split()
    assert raw_txs[0] == raw_txs[1] == raw_txs[2] == open(datafile("signed_csv_2")).read().strip()

    # Summary
    output = get_output(['--show-summary', ] + args, is_liquid=True)
    summary = parse_summary(output)
    assert len(summary) == 3
    assert summary[0]['destination address'] == mock_addresses_liquid[1]['unconfidential_address']
    assert summary[1]['destination address'] == mock_addresses_liquid[0]['unconfidential_address']


@mock.patch('garecovery.liquid_recovery.bitcoincore.AuthServiceProxy')
def test_split_unblinded_csv(mock_bitcoincore):
    """Test Liquid unblinded csv recovery"""
    mock_bitcoincore.return_value = AuthServiceProxy('liquid_txs', is_liquid=True)
    mock_bitcoincore.return_value.getnetworkinfo = mock.Mock(return_value={'version': 180101})
    scantxoutset_result = {
        'success': True,
        'unspents': [{
            'txid': '8481c44d0bd05aad7d3a4f13ff171a62ca6cedaa35e8672ea74c8373e52f1659',
            'vout': 0,
            'scriptPubKey': 'a9143b342bc797467ae910e95fe513334a50773c82b887',
            'desc': 'addr(XGkHDNKrBbAKzE1xEgnGJPdwtH2u7Ag92C)#25yupueg',
            'amountcommitment':
                '09754c21f5e2f1e6f0afac287c9e43f76c5262e2d880d78c42cd98b8eeab64276d',
            'assetcommitment': '0ad8d4ba795b5c8bb4b9fd49515813afa3328eb392c4a197cd70debf6997fe2f67',
            'height': 0,
        }, {
            'txid': '8481c44d0bd05aad7d3a4f13ff171a62ca6cedaa35e8672ea74c8373e52f1659',
            'vout': 1,
            'scriptPubKey': 'a91400d74ffae0ab3b1d61b11e0d621302863183e9a387',
            'desc': 'addr(XBRgnKBGGbStGTqqYohhup7Z7mhNwLU8SS)#25yupueg',
            'amount': 2,
            'asset': 'b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23',
            'height': 0,
        }],
    }
    mock_bitcoincore.return_value.scantxoutset = mock.Mock(return_value=scantxoutset_result)
    mock_bitcoincore.return_value.getblockhash = mock.Mock(return_value='00'*32)
    mock_bitcoincore.return_value.getrawtransaction = mock.Mock(
        return_value=open(datafile('raw_tx_3')).read().strip())
    mock_bitcoincore.return_value.getblockcount.return_value = 144

    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_3.txt')),
        'csv',
        '--network=localtest-liquid',
        '--key-search-depth={}'.format(key_depth),
        '--search-subaccounts={}'.format(sub_depth),
    ]

    # Note that the mockup node does not exactly replicate what core does, thus the transactions
    # created may not be completely realistic, specially for unblinded transactions.

    # Raw tx
    raw_txs = get_output(args, is_liquid=True).strip().split()
    assert raw_txs[0] == raw_txs[1] == open(datafile("signed_csv_3")).read().strip()

    # Summary
    output = get_output(['--show-summary', ] + args, is_liquid=True)
    summary = parse_summary(output)
    assert len(summary) == 2
    assert summary[0]['destination address'] == mock_addresses_liquid[0]['unconfidential_address']

    # Split unblinded transaction
    args += ['--split-unblinded-inputs']

    raw_txs = get_output(args, is_liquid=True).strip().split()
    assert raw_txs[0] == raw_txs[1] == open(datafile("signed_csv_3_split_1")).read().strip()
    assert raw_txs[2] == raw_txs[3] == open(datafile("signed_csv_3_split_2")).read().strip()

    output = get_output(['--show-summary', ] + args, is_liquid=True)
    summary = parse_summary(output)
    assert len(summary) == 4
    assert summary[0]['destination address'] == mock_addresses_liquid[1]['unconfidential_address']
    assert summary[2]['destination address'] == mock_addresses_liquid[0]['unconfidential_address']
