#!/usr/bin/env python3

import decimal
import mock
import wallycore as wally

import garecovery.bitcoin_config
from gaservices.utils import gaconstants, txutil
from garecovery.clargs import DEFAULT_OFILE, DEFAULT_SUBACCOUNT_SEARCH_DEPTH
from .util import (AuthServiceProxy, datafile, get_output, get_output_ex, parse_csv, parse_summary,
                   raise_IOError)


garecovery.bitcoin_config.open = raise_IOError
sub_depth = DEFAULT_SUBACCOUNT_SEARCH_DEPTH
key_depth = 20
default_feerate = 330
destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'


def expect_feerate(fee_satoshi_byte, args=None, is_segwit=False, amount=None, too_big=False):
    """Expect the given feerate

    Callers typically mock estimatesmartfee before calling this
    """
    if args is None:
        args = [
            '--mnemonic-file={}'.format(datafile('mnemonic_2.txt')),
            '--rpcuser=abc',
            '--rpcpassword=abc',
            '2of3',
            '--network=testnet',
            '--recovery-mnemonic-file={}'.format(datafile('mnemonic_3.txt')),
            '--search-subaccounts={}'.format(sub_depth),
            '--destination-address={}'.format(destination_address),
            '--key-search-depth=150',
            '--default-feerate={}'.format(default_feerate),
        ]

    # Raw tx
    if too_big:
        stdout, ofiles = get_output_ex(args + ['--show-summary'])

        summary = parse_summary(stdout)
        assert len(summary) == 1
        assert summary[0]['total out'] == '0.0 BTC'
        assert summary[0]['coin value'] == '0.0 BTC'

        csv = parse_csv(ofiles[DEFAULT_OFILE])
        csv = [row for row in csv]
        assert len(csv) == 1
        assert csv[0]['raw tx'] == '** dust **'

        return

    output = get_output(args).strip()
    output_tx = txutil.from_hex(output)
    assert wally.tx_get_num_outputs(output_tx) == 1
    if is_segwit:
        assert wally.tx_get_witness_count(output_tx) > 0
    else:
        assert wally.tx_get_witness_count(output_tx) == 0

    # Calculate the expected fee
    expected_fee = decimal.Decimal(fee_satoshi_byte * wally.tx_get_vsize(output_tx))

    # The amount of our test tx is a well known value
    if amount is None:
        amount = decimal.Decimal(111110000)
    expected_amount = amount - expected_fee
    actual_amount = wally.tx_get_output_satoshi(output_tx, 0)

    if expected_amount <= 0:
        # If expected amount is negative then the fee exceeds the amount
        # In this case the amount should be small, but not zero
        assert actual_amount > 0
        assert actual_amount < 10
    else:
        # Expect the resultant tx to have a single output with expected amount
        # Calculating the fee is not exact so allow a tolerance
        tolerance = decimal.Decimal(0.001)
        assert actual_amount < (expected_amount * (1+tolerance))
        assert actual_amount > (expected_amount * (1-tolerance))


def _fee_estimate_test(mock_bitcoincore, fee_satoshi_byte, too_big=False):
    """Set fee to fixed amount by mocking estimatesmartfee"""
    mock_bitcoincore.return_value = AuthServiceProxy('raw_2of3_tx_1')

    fee_satoshi_kb = fee_satoshi_byte * 1000
    fee_btc_kb = fee_satoshi_kb / gaconstants.SATOSHI_PER_BTC

    estimate = {'blocks': 3, 'feerate': fee_btc_kb, }
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    expect_feerate(fee_satoshi_byte, too_big=too_big)


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_fee_too_big(mock_bitcoincore):
    """Test that fee too big works"""
    _fee_estimate_test(mock_bitcoincore, 111110000, too_big=True)


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_fee_calculation_with_estimate(mock_bitcoincore):
    """Test that a 'normal' fee works"""
    _fee_estimate_test(mock_bitcoincore, 420)


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_fee_calculation_default_feerate(mock_bitcoincore):
    """Test fee calculation where estimatesmartfee returns an error"""
    mock_bitcoincore.return_value = AuthServiceProxy('raw_2of3_tx_1')

    # estimatesmartfee returns an error if there is not estimate available
    # In this case should fall back to the default
    estimate = {'blocks': 3, 'errors': 'Insufficient data or no feerate found'}
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    expect_feerate(default_feerate)


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_fee_calculation_segwit(mock_bitcoincore):
    """Test fee calculation with a segwit tx thus including the BIP141 transaction weight"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')
    fee_satoshi_byte = 300
    fee_satoshi_kb = decimal.Decimal(fee_satoshi_byte) * 1000
    fee_btc_kb = fee_satoshi_kb / gaconstants.SATOSHI_PER_BTC
    estimate = {'blocks': 3, 'feerate': fee_btc_kb, }
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    destination_address = 'mrZ98U4Vibu9hBMdcdrY5sXpC9Grr3Whpx'
    args = [
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '--mnemonic-file={}'.format(datafile('mnemonic_8.txt')),
        '2of3',
        '--network=testnet',
        '--key-search-depth={}'.format(key_depth),
        '--search-subaccounts={}'.format(sub_depth),
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_9.txt')),
        '--destination-address={}'.format(destination_address),
    ]

    expect_feerate(fee_satoshi_byte, args=args, is_segwit=True, amount=decimal.Decimal(130000000))


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_no_feerate(mock_bitcoincore):
    """Test that feerate must be explicitly provided if not provided by estimatesmartfee"""
    mock_bitcoincore.return_value = AuthServiceProxy('raw_2of3_tx_1')
    estimate = {'blocks': 3, 'errors': 'Insufficient data or no feerate found'}
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_2.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--network=testnet',
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_3.txt')),
        '--search-subaccounts={}'.format(sub_depth),
        '--destination-address={}'.format(destination_address),
        '--key-search-depth=150',
    ]

    output = get_output(args, expect_error=True)
    assert 'you must pass --default-feerate' in output


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_no_feerate_mainnet(mock_bitcoincore):
    """Test that with network mainnet --default-feerate cannot be passed"""
    mock_bitcoincore.return_value = AuthServiceProxy('raw_2of3_tx_1')

    destination_address = '1KGLNQtUhwq1PzckTgdHewFTv8woWDNqHV'
    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_2.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_3.txt')),
        '--search-subaccounts={}'.format(sub_depth),
        '--destination-address={}'.format(destination_address),
        '--default-feerate=123',
        '--key-search-depth=150',
    ]

    output = get_output(args, expect_error=True)
    assert '--default-feerate can be used only in testnet' in output


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_fee_calculation_default_feerate_option(mock_bitcoincore):
    """Test fee calculation where estimatesmartfee returns an error and user provides
    --default-feerate"""
    mock_bitcoincore.return_value = AuthServiceProxy('raw_2of3_tx_1')
    estimate = {'blocks': 3, 'errors': 'Insufficient data or no feerate found'}
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    default_feerate = 123
    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_2.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--network=testnet',
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_3.txt')),
        '--search-subaccounts={}'.format(sub_depth),
        '--destination-address={}'.format(destination_address),
        '--default-feerate=123',
        '--key-search-depth=150',
    ]

    expect_feerate(default_feerate, args)
