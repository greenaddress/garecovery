#!/usr/bin/env python3

import mock

import garecovery.bitcoin_config
from garecovery.clargs import DEFAULT_SUBACCOUNT_SEARCH_DEPTH
from .util import AuthServiceProxy, datafile, get_output, raise_IOError


garecovery.bitcoin_config.open = raise_IOError
sub_depth = DEFAULT_SUBACCOUNT_SEARCH_DEPTH
key_depth = 20
destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_destination_addresses(mock_bitcoincore):
    """Test destination addresses"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')

    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_2.txt')),
        '2of3',
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_3.txt')),
        '--key-search-depth=5',
        '--search-subaccounts={}'.format(sub_depth),
    ]

    valid_destinations_testnet = [
        'mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn',  # p2pkh
        '2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc',  # p2sh
        'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx',  # p2wpkh
        'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7',  # p2wsh
    ]

    valid_destinations_mainnet = [
        '17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem',  # p2pkh
        '3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX',  # p2sh
        'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',  # p2wpkh
        'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3',  # p2wsh
    ]

    invalid_destinations = [
        '',  # empty
        '.',  # unsupported char
        'mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRf',  # invalid checksum base58
        'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzs',  # invalid checksum bech32
        '2v4HUkyGWxntpidUuknvxqc88iE7MFY1CHk',  # unsupported version
        'xx1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfdk2wa',  # unsupported hrp
        '111111111111111111117K4nzc',  # invalid hash len
        'bc1qr508d6qejxtdg4y5r3zarvaryv98gj9p',  # invalid progam len
    ]

    for d in valid_destinations_testnet:
        output = get_output(args + ['--destination-address={}'.format(d), '--network=testnet'])
        assert output == ''

        output = get_output(args + ['--destination-address={}'.format(d), '--network=mainnet'],
                            expect_error=True)
        assert 'Specified network and network inferred from address do not match' in output

    for d in valid_destinations_mainnet:
        output = get_output(args + ['--destination-address={}'.format(d), '--network=mainnet'])
        assert output == ''

        output = get_output(args + ['--destination-address={}'.format(d), '--network=testnet'],
                            expect_error=True)
        assert 'Specified network and network inferred from address do not match' in output

    for d in invalid_destinations:
        output = get_output(args + ['--destination-address={}'.format(d)], expect_error=True)
        assert "Invalid address" in output
