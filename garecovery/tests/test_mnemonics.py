#!/usr/bin/env python

import mock

from .util import datafile, get_output_ex, read_datafile


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
