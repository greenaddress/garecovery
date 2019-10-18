#!/usr/bin/env python3

import mock

import garecovery.recoverycli
from garecovery.clargs import DEFAULT_SUBACCOUNT_SEARCH_DEPTH
from .util import AuthServiceProxy, datafile, get_output, raise_IOError


garecovery.bitcoin_config.open = raise_IOError
sub_depth = DEFAULT_SUBACCOUNT_SEARCH_DEPTH
key_depth = 20
destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'


def test_mnemonic_prompt():
    """Check if --mnemonic-file not passed mnemonic is via prompt"""
    with mock.patch('garecovery.recoverycli.user_input') as user_input_:
        mnemonic = open(datafile('mnemonic_1.txt')).read()
        mnemonic = ' '.join(mnemonic.split())
        user_input_.return_value = mnemonic

        output = get_output([
            '2of2',
            '--network=testnet',
            '--nlocktime-file={}'.format(datafile('compressed_1.zip')),
        ])

        user_input_.assert_called_once_with('mnemonic/hex seed: ')

        tx, private_key_wif = output.split()
        assert tx == open(datafile("signed_2of2_1")).read().strip()
        assert private_key_wif == 'cNVkei2ZVzQLGNTeewPoRZ1hh1jGdt8M5b1GgcJDtWDm1bjjL4Kk'


def test_hex_seed_prompt():
    """Test passing hex seed via prompt"""
    with mock.patch('garecovery.recoverycli.user_input') as user_input_:
        mnemonic = open(datafile('hex_seed_1.txt')).read()
        mnemonic = ' '.join(mnemonic.split())
        user_input_.return_value = mnemonic

        output = get_output([
            '2of2',
            '--nlocktime-file={}'.format(datafile('compressed_1.zip')),
        ])

        user_input_.assert_called_once_with('mnemonic/hex seed: ')

        tx, private_key_wif = output.split()
        assert tx == open(datafile("signed_2of2_1")).read().strip()
        assert private_key_wif == open(datafile("private_key_wif_1")).read().strip()


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

        output = get_output([
            '--rpcuser=abc',
            '--rpcpassword=abc',
            '2of3',
            '--network=testnet',
            '--recovery-mnemonic-file={}'.format(datafile('mnemonic_7.txt')),
            '--key-search-depth={}'.format(key_depth),
            '--search-subaccounts={}'.format(sub_depth),
            '--destination-address={}'.format(destination_address),
        ])

        user_input_.assert_called_once_with('mnemonic/hex seed: ')
        assert output.strip() == open(datafile("signed_2of3_5")).read().strip()


sub_depth = garecovery.clargs.DEFAULT_SUBACCOUNT_SEARCH_DEPTH
key_depth = 20


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

        output = get_output([
            '--mnemonic-file={}'.format(datafile('mnemonic_6.txt')),
            '--rpcuser=abc',
            '--rpcpassword=abc',
            '2of3',
            '--network=testnet',
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

        output = get_output([
            '--rpcuser=abc',
            '--rpcpassword=abc',
            '2of3',
            '--network=testnet',
            '--key-search-depth={}'.format(key_depth),
            '--search-subaccounts={}'.format(sub_depth),
            '--destination-address={}'.format(destination_address),
        ])

        user_input_.assert_has_calls([
            mock.call('mnemonic/hex seed: '),
            mock.call('recovery mnemonic/hex seed: '),
        ])

        assert output.strip() == open(datafile("signed_2of3_5")).read().strip()
