#!/usr/bin/env python

import mock

import garecovery.two_of_three
from .util import AuthServiceProxy, datafile, get_output, get_output_ex, read_datafile


def test_encrypted_mnemonic():
    """Test decryption of mnemonic"""
    for pwd, ok in [('bad', False), ('psw', True)]:
        with mock.patch('garecovery.recoverycli.user_input') as user_input_:
            user_input_.return_value = pwd
            output, ofiles = get_output_ex([
                '--mnemonic-file={}'.format(datafile('mnemonic_1_encrypted.txt')),
                '2of2',
                '--network=testnet',
                '--nlocktime-file={}'.format(datafile('compressed_1.zip')),
            ],
                expect_error=(not ok))

            user_input_.assert_called_once_with('mnemonic password: ')
            if ok:
                assert read_datafile("signed_2of2_1") in ofiles['garecovery.csv']
            else:
                assert 'Incorrect password' in output


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_invalid_mnemonic(mock_bitcoincore):
    """Test invalid mnemonic"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')

    args = [
        '2of3',
        '--network=testnet',
        '--key-search-depth=5',
        '--search-subaccounts=10',
        '--destination-address=mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs',
    ]

    for mnemonic, recovery_mnemonic, expected_error in [
        ('mnemonic_1.txt', 'invalid_word.txt', 'Invalid word: mont'),
        ('invalid_checksum.txt', 'mnemonic_2.txt', 'Invalid mnemonic checksum'),
        ('mnemonic_1.txt', 'invalid_hex_seed.txt', 'hex seed must end with X'),
    ]:
        additional_args = [
            '--mnemonic-file={}'.format(datafile(mnemonic)),
            '--recovery-mnemonic-file={}'.format(datafile(recovery_mnemonic)),
        ]

        output = get_output(args + additional_args, expect_error=True)
        assert expected_error in output
