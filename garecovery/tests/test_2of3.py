#!/usr/bin/env python

import base64
import binascii
import decimal
import logging
import math
import mock
import os
import pytest
import socket
import sys

import bitcoinrpc

import garecovery.recoverycli
import garecovery.clargs
from gaservices.utils import gaconstants, txutil

from .util import (datafile, get_output, parse_summary, verify_txs, get_argparse_error,
                   parse_csv, get_output_ex)
import wallycore as wally


# Patch os.path.exists so that it returns False whenever asked if the default output file exists,
# otherwise all tests will fail by default
def path_exists(filename):
    if filename == garecovery.clargs.DEFAULT_OFILE:
        return False
    return _path_exists(filename)
_path_exists = os.path.exists
garecovery.recoverycli.os.path.exists = path_exists


# Do not read bitcoin config files from filesystem during testing
def raise_IOError(*args):
    raise IOError()
garecovery.bitcoin_config.open = raise_IOError


default_feerate = 330


class AuthServiceProxy:
    """Mock bitcoincore"""

    def __init__(self, txfile):
        self.tx_by_id = {}
        self.txout_by_address = {}
        for line in open(datafile(txfile)).readlines():
            tx = txutil.from_hex(line.strip())
            self.tx_by_id[txutil.get_txhash_bin(tx)] = tx
            for i in range(wally.tx_get_num_outputs(tx)):
                addr = txutil.get_output_address(tx, i, gaconstants.ADDR_VERSIONS_TESTNET)
                self.txout_by_address[addr] = (tx, i)
        self.imported = {}

        # This is something of a workaround because all the existing tests are based on generating
        # txs where nlocktime was fixed as 0. The code changed to use current blockheight, so by
        # fudging this value to 0 the existing tests don't notice the difference
        self.getblockcount.return_value = 0

    def importmulti(self, requests):
        result = []
        for request in requests:
            assert request['watchonly'] is True
            address = request['scriptPubKey']['address']
            if address in self.txout_by_address:
                self.imported[address] = self.txout_by_address[address]
            result.append({'success': True})
        return result

    def _get_unspent(self, address):
        imported = self.imported.get(address, None)
        if imported is None:
            return None
        tx, i = imported
        script = wally.tx_get_output_script(tx, i)
        return {
            "txid": txutil.get_txhash_bin(tx),
            "vout": i,
            "address": address,
            "scriptPubKey": wally.hex_from_bytes(script)
        }

    def listunspent(self, minconf, maxconf, addresses):
        unspent = [self._get_unspent(address) for address in addresses]
        return [x for x in unspent if x]

    def getrawtransaction(self, txid):
        return txutil.to_hex(self.tx_by_id[txid])

    def batch_(self, requests):
        return [getattr(self, call)(params) for call, params in requests]

    estimatesmartfee = mock.Mock()
    getblockcount = mock.Mock()
    getnewaddress = mock.Mock()


# Patch open into bitcoincore to return a fixed config file
mock_read_data = """
rpcuser=rpcuser__
rpcpassword=rpcpassword__
rpcport=rpcport__
"""
bitcoincore_open = mock.mock_open(read_data=mock_read_data)
garecovery.two_of_three.bitcoincore.open = bitcoincore_open
sub_depth = garecovery.clargs.DEFAULT_SUBACCOUNT_SEARCH_DEPTH
key_depth = 20


def expect_feerate(fee_satoshi_byte, args=None, is_segwit=False, amount=None, too_big=False):
    """Expect the given feerate

    Callers typically mock estimatesmartfee before calling this
    """
    if args is None:
        destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'
        args = [
            '--mnemonic-file={}'.format(datafile('mnemonic_2.txt')),
            '--rpcuser=abc',
            '--rpcpassword=abc',
            '2of3',
            '--recovery-mnemonic-file={}'.format(datafile('mnemonic_3.txt')),
            '--rescan',
            '--search-subaccounts={}'.format(sub_depth),
            '--destination-address={}'.format(destination_address),
            '--key-search-depth=150',
            '--default-feerate={}'.format(default_feerate),
        ]

    # Raw tx
    if too_big:
        stdout, ofiles = get_output_ex(args)

        summary = parse_summary(stdout)
        assert len(summary) == 1
        assert summary[0]['total out'] == '0.0 BTC'
        assert summary[0]['coin value'] == '0.0 BTC'

        csv = parse_csv(ofiles[garecovery.clargs.DEFAULT_OFILE])
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
    """Test fee calculation where estimatesmartfee return -1"""
    mock_bitcoincore.return_value = AuthServiceProxy('raw_2of3_tx_1')

    # estimatesmartfee returns -1 if there is not estimate available
    # In this case should fall back to the default
    estimate = {'blocks': 3, 'feerate': decimal.Decimal(-1)}
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
        '--rescan',
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
    estimate = {'blocks': 3, 'feerate': decimal.Decimal(-1)}
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'
    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_2.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_3.txt')),
        '--search-subaccounts={}'.format(sub_depth),
        '--destination-address={}'.format(destination_address),
        '--key-search-depth=150',
    ]

    output = get_output(args, expect_error=True)
    assert 'you must pass --default-feerate' in output


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_no_feerate_mainnet(mock_bitcoincore):
    """Test that with a mainnet address --default-feerate is ignored"""
    mock_bitcoincore.return_value = AuthServiceProxy('raw_2of3_tx_1')
    estimate = {'blocks': 3, 'feerate': decimal.Decimal(-1)}
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    default_feerate = 123
    destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'
    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_2.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_3.txt')),
        '--rescan',
        '--search-subaccounts={}'.format(sub_depth),
        '--destination-address={}'.format(destination_address),
        '--default-feerate=123',
        '--key-search-depth=150',
    ]

    with mock.patch('garecovery.two_of_three.is_testnet_address', side_effect=[True, False]):
        output = get_output(args, expect_error=True)
        assert 'Unable to get fee rate from core' in output
        assert 'ignoring --default-feerate' in output


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_fee_calculation_default_feerate_option(mock_bitcoincore):
    """Test fee calculation where estimatesmartfee return -1 and user provides --default-feerate"""
    mock_bitcoincore.return_value = AuthServiceProxy('raw_2of3_tx_1')
    estimate = {'blocks': 3, 'feerate': decimal.Decimal(-1)}
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    default_feerate = 123
    destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'
    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_2.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_3.txt')),
        '--rescan',
        '--search-subaccounts={}'.format(sub_depth),
        '--destination-address={}'.format(destination_address),
        '--default-feerate=123',
        '--key-search-depth=150',
    ]

    expect_feerate(default_feerate, args)


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_recover_2of3(mock_bitcoincore):
    """Test 2of3 happy path"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')

    estimate = {'blocks': 3, 'feerate': 1, }
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'
    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_6.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_7.txt')),
        '--rescan',
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

    destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'
    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_6.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_7.txt')),
        '--rescan',
        '--key-search-depth={}'.format(key_depth),
        '--search-subaccounts={}'.format(sub_depth),
        '--destination-address={}'.format(destination_address),
    ]

    output = get_output(args).strip()
    tx = txutil.from_hex(output)
    assert wally.tx_get_locktime(tx) == current_blockheight


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_provide_xpub(mock_bitcoincore):
    """Test --ga-xpub option"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')

    estimate = {'blocks': 3, 'feerate': 1, }
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'
    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_8.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_10.txt')),
        '--rescan',
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
def test_no_xpub_hex_seeds(mock_bitcoincore):
    """If you do not provide a mnemonic (but a hex seed) you must provide xpub"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')

    estimate = {'blocks': 3, 'feerate': 1, }
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'

    xpub = 'tpubEDNQxNxDqhj7Qoyv7ELkQShpL1qdFWePuTnVzX4civm9Tt7an3MLVXfr'\
           'v7VNA29HCLejMoLK8oLkGV5mupFt7LhWQ4CCRYXoMcfvx3dDJs4'
    args = [
        '--mnemonic-file={}'.format(datafile('hex_seed_8.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--recovery-mnemonic-file={}'.format(datafile('hex_seed_10.txt')),
        '--rescan',
        '--key-search-depth={}'.format(key_depth),
        '--search-subaccounts={}'.format(sub_depth),
        '--destination-address={}'.format(destination_address),
    ]

    output = get_output(args, True)
    assert 'You must either pass --ga-xpub or a mnemonic' in output


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_hex_seeds(mock_bitcoincore):
    """Test providing hex seeds instead of mnemonics"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')

    estimate = {'blocks': 3, 'feerate': 1, }
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'

    xpub = 'tpubEDNQxNxDqhj7Qoyv7ELkQShpL1qdFWePuTnVzX4civm9Tt7an3MLVXfr'\
           'v7VNA29HCLejMoLK8oLkGV5mupFt7LhWQ4CCRYXoMcfvx3dDJs4'
    args = [
        '--mnemonic-file={}'.format(datafile('hex_seed_8.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--recovery-mnemonic-file={}'.format(datafile('hex_seed_10.txt')),
        '--rescan',
        '--key-search-depth={}'.format(key_depth),
        '--destination-address={}'.format(destination_address),
        '--ga-xpub={}'.format(xpub),
    ]

    assert get_output(args).strip() == open(datafile('signed_2of3_6')).read().strip()


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_xpub_and_subaccount_search(mock_bitcoincore):
    """Test that the options --ga-xpub and --search-subaccounts are mutually exlcusive"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')
    estimate = {'blocks': 3, 'feerate': 1, }
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate
    destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'
    xpub = 'tpubEDNQxNxDqhj7Qoyv7ELkQShpL1qdFWePuTnVzX4civm9Tt7an3MLVXfr'\
           'v7VNA29HCLejMoLK8oLkGV5mupFt7LhWQ4CCRYXoMcfvx3dDJs4'
    args = [
        '--mnemonic-file={}'.format(datafile('hex_seed_8.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--recovery-mnemonic-file={}'.format(datafile('hex_seed_10.txt')),
        '--rescan',
        '--key-search-depth={}'.format(key_depth),
        '--destination-address={}'.format(destination_address),
        '--search-subaccounts',
        '--ga-xpub={}'.format(xpub),
    ]

    output = get_argparse_error(args)
    assert '--ga-xpub: not allowed with argument --search-subaccounts' in output


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_custom_prv(mock_bitcoincore):
    """Test --custom-xprv option"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')

    estimate = {'blocks': 3, 'feerate': 1, }
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'
    custom_xprv = 'tprv8ZgxMBicQKsPcuswzN4iZ7jhs3mghK6JUDXJvQM4wQac7cGvtSFpx24uF'\
                  'Chjvs2DDi6ZqGXjmwXHwWBcZtVMeMGKzqDSbxczJDZRepXNQfo'
    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_8.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--custom-xprv={}'.format(custom_xprv),
        '--rescan',
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
    destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'
    custom_xprv = 'tprv8ZgxMBicQKsPcuswzN4iZ7jhs3mghK6JUDXJvQM4wQac7cGvtSFpx24uF'\
                  'Chjvs2DDi6ZqGXjmwXHwWBcZtVMeMGKzqDSbxczJDZRepXNQfo'
    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_8.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_10.txt')),
        '--custom-xprv={}'.format(custom_xprv),
        '--rescan',
        '--key-search-depth={}'.format(key_depth),
        '--search-subaccounts={}'.format(sub_depth),
        '--destination-address={}'.format(destination_address),
    ]

    output = get_argparse_error(args)
    assert '--custom-xprv: not allowed with argument --recovery-mnemonic-file' in output


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_prompt_for_mnemonic(mock_bitcoincore):
    """Test prompting for mnemonic"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')

    estimate = {'blocks': 3, 'feerate': 1, }
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    with mock.patch('garecovery.recoverycli.user_input') as user_input_:

        mnemonic = open(datafile('mnemonic_6.txt')).read().strip()
        mnemonic = ' '.join(mnemonic.split())
        user_input_.return_value = mnemonic

        destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'
        output = get_output([
            '--rpcuser=abc',
            '--rpcpassword=abc',
            '2of3',
            '--recovery-mnemonic-file={}'.format(datafile('mnemonic_7.txt')),
            '--rescan',
            '--key-search-depth={}'.format(key_depth),
            '--search-subaccounts={}'.format(sub_depth),
            '--destination-address={}'.format(destination_address),
        ])

        user_input_.assert_called_once_with('mnemonic/hex seed: ')
        assert output.strip() == open(datafile("signed_2of3_5")).read().strip()


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_prompt_for_recovery_mnemonic(mock_bitcoincore):
    """Test prompting for recovery mnemonic"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')

    estimate = {'blocks': 3, 'feerate': 1, }
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    with mock.patch('garecovery.recoverycli.user_input') as user_input_:

        recovery_mnemonic = open(datafile('mnemonic_7.txt')).read()
        recovery_mnemonic = ' '.join(recovery_mnemonic.split())
        user_input_.return_value = recovery_mnemonic

        destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'
        output = get_output([
            '--mnemonic-file={}'.format(datafile('mnemonic_6.txt')),
            '--rpcuser=abc',
            '--rpcpassword=abc',
            '2of3',
            '--rescan',
            '--search-subaccounts={}'.format(sub_depth),
            '--key-search-depth={}'.format(key_depth),
            '--destination-address={}'.format(destination_address),
        ])

        user_input_.assert_called_once_with('recovery mnemonic/hex seed: ')
        assert output.strip() == open(datafile("signed_2of3_5")).read().strip()


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_prompt_for_both_mnemonics(mock_bitcoincore):
    """Test prompting for both mnemonic and recovery mnemonic"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')

    estimate = {'blocks': 3, 'feerate': 1, }
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    with mock.patch('garecovery.recoverycli.user_input') as user_input_:

        mnemonic = open(datafile('mnemonic_6.txt')).read()
        mnemonic = ' '.join(mnemonic.split())

        recovery_mnemonic = open(datafile('mnemonic_7.txt')).read()
        recovery_mnemonic = ' '.join(recovery_mnemonic.split())

        user_input_.side_effect = (mnemonic, recovery_mnemonic)

        destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'
        output = get_output([
            '--rpcuser=abc',
            '--rpcpassword=abc',
            '2of3',
            '--rescan',
            '--key-search-depth={}'.format(key_depth),
            '--search-subaccounts={}'.format(sub_depth),
            '--destination-address={}'.format(destination_address),
        ])

        user_input_.assert_has_calls([
            mock.call('mnemonic/hex seed: '),
            mock.call('recovery mnemonic/hex seed: '),
        ])

        assert output.strip() == open(datafile("signed_2of3_5")).read().strip()


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_importmulti_error(mock_bitcoincore):
    """Test handing of importmulti errors"""
    mock_bitcoincore.return_value.importmulti = mock.Mock(return_value=[{'success': False}, ])

    destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'
    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_2.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_3.txt')),
        '--key-search-depth=5',
        '--rescan',
        '--search-subaccounts={}'.format(sub_depth),
        '--destination-address={}'.format(destination_address),
    ]
    output = get_output(args, expect_error=True)
    assert 'Unexpected result from importmulti' in output


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

        destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'
        return [
            '--mnemonic-file={}'.format(datafile('mnemonic_2.txt')),
            '--rpcuser=abc',
            '--rpcpassword=abc',
            '2of3',
            '--recovery-mnemonic-file={}'.format(datafile('mnemonic_3.txt')),
            '--key-search-depth={}'.format(key_search_depth),
            '--rescan',
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


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_missing_config_file_no_params(mock_bitcoincore):
    """Test missing config file"""
    with mock.patch('garecovery.two_of_three.bitcoincore.Connection.read_config'):
        @staticmethod
        def _read_config(keys, options):
            return {}
        garecovery.two_of_three.bitcoincore.Connection.read_config = _read_config

        config_filename = '/non/existent/file'

        destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'
        output = get_output([
            '--mnemonic-file={}'.format(datafile('mnemonic_2.txt')),
            '--config-filename={}'.format(config_filename),
            '2of3',
            '--recovery-mnemonic-file={}'.format(datafile('mnemonic_3.txt')),
            '--rescan',
            '--key-search-depth={}'.format(key_depth),
            '--search-subaccounts={}'.format(sub_depth),
            '--destination-address={}'.format(destination_address),
        ],
            expect_error=True)

        msg = "not found in config file"
        assert msg in output


def check_http_auth(HTTPConnection, args, hostname, port, timeout, auth_data):
    try:
        get_output(args, True)
    except bitcoinrpc.authproxy.JSONRPCException:
        # Expect the test to completely fail because HTTPConnection is a mock
        pass

    # However before failing it should have connected...
    assert HTTPConnection.call_args_list == [
        mock.call(hostname, port, timeout=timeout),
    ]

    # .. and attempted a POST with the correct basic auth header
    expected_auth = "Basic {}".format(base64.b64encode(auth_data))
    request_calls = HTTPConnection.return_value.request.call_args_list
    assert request_calls[0][0][3]['Authorization'] == expected_auth


@mock.patch('bitcoinrpc.authproxy.httplib.HTTPConnection')
def test_authenticate_password(HTTPConnection):
    """Test rpcpassword/rpcuser authentication"""
    destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'
    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_6.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_7.txt')),
        '--rescan',
        '--key-search-depth={}'.format(key_depth),
        '--search-subaccounts={}'.format(sub_depth),
        '--destination-address={}'.format(destination_address),
    ]

    check_http_auth(HTTPConnection, args, '127.0.0.1', 18332, 3600, b'abc:abc')


@mock.patch('bitcoinrpc.authproxy.httplib.HTTPConnection')
def test_authenticate_cookiefile(HTTPConnection):
    """Test rpcpassword/rpcuser authentication"""
    destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'
    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_6.txt')),
        '2of3',
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_7.txt')),
        '--rescan',
        '--key-search-depth={}'.format(key_depth),
        '--search-subaccounts={}'.format(sub_depth),
        '--destination-address={}'.format(destination_address),
    ]

    # Because of the way mock_read has been used to return a fixed string representing a config
    # file, reading the cookiefile will also return this config file, however for the purposes
    # of the unit test it doesn't matter
    cookie = mock_read_data.strip().encode("ascii")
    check_http_auth(HTTPConnection, args, '127.0.0.1', 18332, 3600, cookie)


def test_core_daemon_not_available():
    """Test core not available"""
    rpcuser = 'rpcuser__'
    rpcpassword = 'rpcpassword__'
    rpcconnect = 'rpcconnect__'
    rpcport = 'rpcport__'
    rpctimeout = 123

    def no_core(connstr, http_auth_header, timeout):
        # Check that the connection string is formed correctly from
        # the passed args, but then refuse to connect
        # The x.y is part of a workaround for authentication via python-bitcoinrpc
        assert connstr == "http://x:y@{}:{}".format(rpcconnect, rpcport)
        assert timeout == rpctimeout*60
        raise socket.error('[Errno 111] Connection refused')

    with mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy', no_core):

        destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'
        output = get_output([
            '--mnemonic-file={}'.format(datafile('mnemonic_2.txt')),
            '--rpcuser={}'.format(rpcuser),
            '--rpcpassword={}'.format(rpcpassword),
            '--rpcconnect={}'.format(rpcconnect),
            '--rpcport={}'.format(rpcport),
            '--rpc-timeout-minutes={}'.format(rpctimeout),
            '2of3',
            '--recovery-mnemonic-file={}'.format(datafile('mnemonic_3.txt')),
            '--rescan',
            '--key-search-depth={}'.format(key_depth),
            '--search-subaccounts={}'.format(sub_depth),
            '--destination-address={}'.format(destination_address),
        ],
            expect_error=True)

        assert "Failed to connect" in output


def _verify(mnemonic_filename, recovery_mnemonic_filename, utxos, expect_witness):
    """Verify tx signatures"""
    destination_address = 'mrZ98U4Vibu9hBMdcdrY5sXpC9Grr3Whpx'
    output = get_output([
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '--mnemonic-file={}'.format(datafile(mnemonic_filename)),
        '2of3',
        '--rescan',
        '--key-search-depth={}'.format(key_depth),
        '--search-subaccounts={}'.format(sub_depth),
        '--recovery-mnemonic-file={}'.format(datafile(recovery_mnemonic_filename)),
        '--destination-address={}'.format(destination_address),
    ])

    txs = [output for output in output.strip().split("\n")]
    assert len(txs) == 1
    verify_txs(txs, utxos, expect_witness)


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_verify_nonsegwit(mock_bitcoincore):
    """Sign a non-segwit tx and check signatures"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')

    estimate = {'blocks': 3, 'feerate': 1, }
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    utxos = [
        # testnet: 58af3d22990d7b5bd69e720290cef37882216b927a8edd73ee3e0d0a71a31af6
        """01000000013079137ed67e644e1182e1d8bf4d36129b3226eeb07d95268c08d58540d
79580010000006a47304402206019340fa6d8da5e342f3094d4b781cf9ddf0c53f3c14ebf3dfa6fc
4c687769402202a26fbff1c0348a5adcee720d0d7e99129f3a0bbe93517a8dd99d63d018f4c0a012
103bf8bff049dbc329f588c7dc6be32f1fd89bf5e51459258224823caf7b627201bffffffff0280a
4bf070000000017a9146245b6439e9848658cf8e7cfbd394efe9752329487aa0c37361b000000197
6a9143a3b7fb9fd7438a83d20d6f8244d6e3bb4daa28688ac00000000""",
    ]

    _verify(
        'mnemonic_6.txt',
        'mnemonic_7.txt',
        utxos,
        False,
    )


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_verify_segwit(mock_bitcoincore):
    """Sign a segwit tx and check signatures"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')

    estimate = {'blocks': 3, 'feerate': 1, }
    mock_bitcoincore.return_value.estimatesmartfee.return_value = estimate

    utxos = [
        # testnet: 8b548d8bee9b5177cedfafe491d71f757e29da220ca20b6e0ea1677fab7dc642
        """0100000001dc3f1f69739082361216f858228ee19e39ffadb22de0201ca9ee6cc83d3
82d31010000006b483045022100b635bf496499f03aceda59b5879a73fbb90208096f887b40b1a8b
4319c296e0a022000b37843dbaa3ea3da1bbe6be3757a7ed51eb2e1c5778de6c4b0ddef8133bed10
12102242381f8b58a4e173327f701fa9342d24cd99d80c2a60a1d3bc3800f59a6b258ffffffff028
0a4bf070000000017a914ab85000633ae44082c689cb07b578c4d81f99a5587cb4c421c450000001
976a914093cc1bb39c19264ea29f713ce6d7ef67c73a35288ac00000000""",
    ]

    _verify(
        'mnemonic_8.txt',
        'mnemonic_9.txt',
        utxos,
        True,
    )
