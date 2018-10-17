#!/usr/bin/env python

import mock
import pytest

import garecovery.bitcoincore
from garecovery.clargs import DEFAULT_OFILE
from .util import (datafile, get_output, get_output_ex, parse_csv, parse_summary, path_exists,
                   read_datafile)


garecovery.recoverycli.os.path.exists = path_exists


@mock.patch('garecovery.bitcoincore.AuthServiceProxy', None)
@mock.patch('garecovery.recoverycli.os.path.exists', lambda filename: True)
def test_ofile_exists():
    """Test that an appropriate error is returned if the output file exists"""
    output, ofiles = get_output_ex([
        '--mnemonic-file={}'.format(datafile('mnemonic_1.txt')),
        '2of2',
        '--network=testnet',
        '--nlocktime-file={}'.format(datafile('compressed_1.zip')),
    ],
        expect_error=True)
    assert 'already exists' in output


@mock.patch('garecovery.bitcoincore.AuthServiceProxy', None)
def test_no_transactions():
    """Test that an nlocktimes.zip with no transactions generates a meaningful diagnostic"""
    output, ofiles = get_output_ex([
        '--mnemonic-file={}'.format(datafile('mnemonic_12.txt')),
        '2of2',
        '--network=testnet',
        '--nlocktime-file={}'.format(datafile('empty_nlocktimes.zip')),
    ],
        expect_error=True)
    assert 'contains no transactions' in output


def test_missing_nlocktime_arg():
    """Check error message if required nlocktime filename not passed"""
    class Exit(Exception):
        pass
    with mock.patch('argparse.ArgumentParser.exit',
                    side_effect=Exit()) as exit_:

        try:
            output = get_output([
                '--mnemonic-file={}'.format(datafile('mnemonic_1.txt')),
                '2of2',
                '--network=testnet',
            ])
        except Exit:
            msg = 'argument --nlocktime-file is required'
            exit_.assert_called_once()
            assert exit_.call_args[0][0] == 2
            assert '--nlocktime-file' in exit_.call_args[0][1]
            assert 'required' in exit_.call_args[0][1]


@mock.patch('garecovery.bitcoincore.AuthServiceProxy', None)
def test_standard_segwit():
    """Standard case with segwit"""
    output = get_output([
        '--mnemonic-file={}'.format(datafile('mnemonic_4.txt')),
        '--show-summary',
        '2of2',
        '--network=testnet',
        '--nlocktime-file={}'.format(datafile('nlocktimes_1.zip')),
    ])
    summary = parse_summary(output)
    assert len(summary) == 1
    assert summary[0]['destination address'] == 'momxJW75A8PoiiJhCPGmiC4rTsE7yGLVyh'


def do_test_standard_summary(nlocktimes_filename):
    output, ofiles = get_output_ex([
        '--mnemonic-file={}'.format(datafile('mnemonic_1.txt')),
        '2of2',
        '--network=testnet',
        '--show-summary',
        '--nlocktime-file={}'.format(datafile(nlocktimes_filename)),
    ])
    summary = parse_summary(output)

    assert len(summary) == 1
    summary = summary[0]

    csv = ofiles[DEFAULT_OFILE]
    csv = parse_csv(csv)
    csv = [row for row in csv]
    assert len(csv) == 1
    csv = csv[0]

    # Fields only in csv
    assert csv['private key'] == 'cNVkei2ZVzQLGNTeewPoRZ1hh1jGdt8M5b1GgcJDtWDm1bjjL4Kk'
    assert 'private key' not in summary
    assert csv['raw tx'] == (
        '0100000001433981a3c9e1f73150d2593a10bd5feb2748e80b96fb3a173ac7405d08a571c500000'
        '000da00483045022100fb9a5343847f58f6cb40350b6d9eb065db0fc2ef95c70e1088e17803448be'
        'af8022007bd03f75180ca680056f5dd0d03e7785f0f1a64f3a3b2b2e705af5170e06bf7014730440'
        '2203683f68c1c9a1aa514fc2198d66b93a0b23eee6a659ff45214dbf3e939df671e02205381b82ba'
        'a99d18a6a667b7d70a0c832b78d263ec2182c654e9dd8715f9f09ca0147522103c905edf97e48915'
        'd8b43a8076c0815f20c455e233e02c2eb07e774319656d8a92103d969823e57499e4d840b4970033'
        'a12c0ea0d2bd8b4830c0fa674c2d4153d2b0952aefeffffff01e4d4f505000000001976a91414335'
        'dd02d583daaeece04930ede0acefccf875688ac33040000'
    )
    assert 'raw tx' not in summary

    # Common fields
    for format_ in summary, csv:
        assert format_['coin value'] == '0.999969 BTC'
        assert format_['total out'] == '0.999969 BTC'
        assert format_['lock time'] == '1075'
        assert format_['tx id'] == ('acd2c5694a91eeeab07178ab9cd6c4b'
                                    '7c57457e561b43120b6c78dbc4a5bf96a')
        assert format_['destination address'] == 'mhMmLtqyR9VgGXAg8dUmCnPtJS8gbMqGRL'


@mock.patch('garecovery.bitcoincore.AuthServiceProxy', None)
def test_standard_summary():
    """Standard case - check summary"""
    do_test_standard_summary('compressed_1.zip')


@mock.patch('garecovery.bitcoincore.AuthServiceProxy', None)
def test_standard_summary_old_nlocktimes():
    """Standard case - check summary"""
    do_test_standard_summary('compressed_1_old.zip')


@mock.patch('garecovery.bitcoincore.AuthServiceProxy', None)
def test_seed_gait_derivation():
    """Wallets created using a hardware wallet use a different algorithm to derive the gait path"""
    output = get_output([
        '--mnemonic-file={}'.format(datafile('mnemonic_hw_2.txt')),
        '--show-summary',
        '2of2',
        '--network=testnet',
        '--nlocktime-file={}'.format(datafile('nlocktimes_hw_2.zip')),
    ])
    summary = parse_summary(output)
    assert len(summary) == 1
    assert summary[0]['destination address'] == 'n2XzrydLuz1cAdP9m4tRrv98LNVfu9Q5u8'


@pytest.mark.parametrize("current_blockcount, nlocktime_message", [
    ('787', '1075 (288 blocks/~2 days to go)'),
    ('930', '1075 (145 blocks/~1 day to go)'),
    ('931', '1075 (144 blocks/~1 day to go)'),
    ('932', '1075 (143 blocks/~23 hours to go)'),
    ('1063', '1075 (12 blocks/~2 hours to go)'),
    ('1064', '1075 (11 blocks/~1 hour to go)'),
    ('1069', '1075 (6 blocks/~1 hour to go)'),
    ('1070', '1075 (5 blocks/~50 minutes to go)'),
    ('1074', '1075 (1 block/~10 minutes to go)'),
    ('1075', '1075 *spendable now'),
    ])
def test_nlocktime_str(current_blockcount, nlocktime_message):
    """Test the nlocktime summary string"""
    output = get_output([
        '--mnemonic-file={}'.format(datafile('mnemonic_1.txt')),
        '--show-summary',
        '--current-blockcount={}'.format(current_blockcount),
        '2of2',
        '--network=testnet',
        '--nlocktime-file={}'.format(datafile('compressed_1.zip')),
    ])
    summary = parse_summary(output)
    assert len(summary) == 1
    assert summary[0]['destination address'] == 'mhMmLtqyR9VgGXAg8dUmCnPtJS8gbMqGRL'
    assert summary[0]['lock time'] == nlocktime_message


def test_standard_result():
    """Standard case - check raw transaction returned"""
    output = get_output([
        '--mnemonic-file={}'.format(datafile('mnemonic_1.txt')),
        '2of2',
        '--network=testnet',
        '--nlocktime-file={}'.format(datafile('compressed_1.zip')),
    ])

    tx, private_key_wif = output.split()
    assert tx == read_datafile("signed_2of2_1")
    assert private_key_wif == 'cNVkei2ZVzQLGNTeewPoRZ1hh1jGdt8M5b1GgcJDtWDm1bjjL4Kk'


def test_unmatching_networks():
    """Test specified network and inferred network not matching"""

    for network, mnemonic, nlocktime_file in [
        ('testnet', 'hex_seed_1.txt', 'compressed_1.zip'),
        ('mainnet', 'mnemonic_4.txt', 'nlocktimes_1.zip'),
    ]:
        output = get_output([
            '2of2',
            '-n={}'.format(network),
            '--mnemonic={}'.format(datafile(mnemonic)),
            '--nlocktime-file={}'.format(datafile(nlocktime_file)),
        ], expect_error=True)

        assert 'Specified network and network inferred from nlocktime file do not match' in output
