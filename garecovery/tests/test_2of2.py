#!/usr/bin/env python

import mock
import pytest
import sys

import garecovery.recoverycli

from .util import *


# Patch os.path.exists so that it returns False whenever asked if the default output file exists,
# otherwise all tests will fail by default
def path_exists(filename):
    if filename == garecovery.clargs.DEFAULT_OFILE:
        return False
    return _path_exists(filename)
_path_exists = os.path.exists
garecovery.recoverycli.os.path.exists = path_exists


@mock.patch('garecovery.bitcoincore.AuthServiceProxy', None)
def test_no_transactions():
    """Test that an nlocktimes.zip with no transactions generates a meaningful diagnostic"""
    output, ofiles = get_output_ex([
        '--mnemonic-file={}'.format(datafile('mnemonic_12.txt')),
        '2of2',
        '--nlocktime-file={}'.format(datafile('empty_nlocktimes.zip')),
    ],
        expect_error=True)
    assert 'contains no transactions' in output


@mock.patch('garecovery.bitcoincore.AuthServiceProxy', None)
@mock.patch('garecovery.recoverycli.os.path.exists', lambda filename: True)
def test_ofile_exists():
    """Test that an appropriate error is returned if the output file exists"""
    output, ofiles = get_output_ex([
        '--mnemonic-file={}'.format(datafile('mnemonic_1.txt')),
        '2of2',
        '--nlocktime-file={}'.format(datafile('compressed_1.zip')),
    ],
        expect_error=True)
    assert 'already exists' in output


@mock.patch('garecovery.bitcoincore.AuthServiceProxy', None)
def test_standard_segwit():
    """Standard case with segwit"""
    output = get_output([
        '--mnemonic-file={}'.format(datafile('mnemonic_4.txt')),
        '--show-summary',
        '2of2',
        '--nlocktime-file={}'.format(datafile('nlocktimes_1.zip')),
    ])
    summary = parse_summary(output)
    assert len(summary) == 1
    assert summary[0]['destination address'] == 'momxJW75A8PoiiJhCPGmiC4rTsE7yGLVyh'


def do_test_standard_summary(nlocktimes_filename):
    output, ofiles = get_output_ex([
        '--mnemonic-file={}'.format(datafile('mnemonic_1.txt')),
        '2of2',
        '--nlocktime-file={}'.format(datafile(nlocktimes_filename)),
    ])
    summary = parse_summary(output)

    assert len(summary) == 1
    summary = summary[0]

    csv = ofiles[clargs.DEFAULT_OFILE]
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
        '--nlocktime-file={}'.format(datafile('nlocktimes_hw_2.zip')),
    ])
    summary = parse_summary(output)
    assert len(summary) == 1
    assert summary[0]['destination address'] == 'n2XzrydLuz1cAdP9m4tRrv98LNVfu9Q5u8'


@mock.patch('garecovery.bitcoincore.AuthServiceProxy', None)
def test_hex_seed_login():
    """Test that it's possible to use a hex seed rather than mnemonic"""
    output = get_output([
        '--mnemonic-file={}'.format(datafile('hex_seed_hw_2.txt')),
        '--show-summary',
        '2of2',
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
        '--nlocktime-file={}'.format(datafile('compressed_1.zip')),
    ])
    summary = parse_summary(output)
    assert len(summary) == 1
    assert summary[0]['destination address'] == 'mhMmLtqyR9VgGXAg8dUmCnPtJS8gbMqGRL'
    assert summary[0]['lock time'] == nlocktime_message


def read_datafile(filename):
    return open(datafile(filename)).read().strip()


def test_standard_result():
    """Standard case - check raw transaction returned"""
    output = get_output([
        '--mnemonic-file={}'.format(datafile('mnemonic_1.txt')),
        '2of2',
        '--nlocktime-file={}'.format(datafile('compressed_1.zip')),
    ])

    tx, private_key_wif = output.split()
    assert tx == read_datafile("signed_2of2_1")
    assert private_key_wif == 'cNVkei2ZVzQLGNTeewPoRZ1hh1jGdt8M5b1GgcJDtWDm1bjjL4Kk'


def _verify(mnemonic_filename, nlocktimes_filename, expect_witness, utxos):
    output = get_output([
        '--mnemonic-file={}'.format(datafile(mnemonic_filename)),
        '2of2',
        '--nlocktime-file={}'.format(datafile(nlocktimes_filename)),
    ])

    outputs = [output.split() for output in output.strip().split("\n")]
    txs = [tx for tx, _ in outputs]

    verify_txs(txs, utxos, expect_witness)


def test_verify_segwit():
    utxos = [
        # 1105ee5881ebbb3be09ca084800b1ea75a10ed5e2e900b32e40b9c89b1828381
        """0100000000010117b0bac3c5f292d142793a6ec500b9829b7d9114db9a8147ab8ccb7
fd35b2b540000000023220020a73fba3cc606348502717b31f168637e7a1d5af62882d0fc3e647d0
ffb80b94ffdffffff01ab6fbf070000000017a91455db84e79a6ab81fee694e36624aeee537a6d3d
c870400483045022100837f88e79c3bea1f569c65ee728e9e7a88b59642153100203861e59afd5bb
8d102207565b54554bc066e75524e1a424018a636229cc3c42f3b27f4fce90a613c1002014730440
2204007dd25ba9366b4b2ef0cea6b3ff1848891015a40629541d91f74ea55dd3ee9022044ce3968d
bf29666efafaab076f5ce82a112d03532eb628efce4c4aa652b35b5014752210336a19772ec3cf73
10e1cbc881e22a6db07473014a638f43e6e98ea330615d973210214eee64627d121e3bc51174c7f2
76006c864083a58a510eb71242a0f6495fa5952aee2961100""",

        # 7c6cfbe0521ec4549c1c0e085beebdb59a74a91a151ac37098639200b6ca23eb
        """0100000001be0bf9855097941ab0eeea3f3664aac906f2d9ffd2360a70f0933929232a0
dcb010000006b483045022100b0f3d40cf5f4abaa7de7b056e9d96b9b35e25fbfaa9e68d5cb5ac83
78eb7035102204cbf3566470ca106212eaea9bf4e64d147bac4bcf18d3e8eb6a5365d6f57df9d012
10232c80b335e8ef9a5080357c6f6c10b54a129c1ce7164d726ee4f37f247d1be13ffffffff0280a
4bf070000000017a91495f02d823f5d8f68f73db87d2346ad86968f066387cb3e0f1e2e000000197
6a914814d160ef5b406831a24f68c436924239f75c78188ac00000000""",
    ]

    _verify(
        'mnemonic_5.txt',
        'nlocktimes_2.zip',
        True,
        utxos,
        )


def test_verify_nonsegwit():
    _verify(
        'mnemonic_6.txt',
        'nlocktimes_3.zip',
        False,
        [
            """0100000001a397532695d3038fe6ecddfbec14313f465b1163b3912933da1e6b2
f67839574010000006b483045022100b14e8ba4f50ec85d599361c4b35a949875e02fd08756bfab2
1020d8e9f5ad766022024aeeee12573eddab72431a4412958b032d2738b9017d0754fe34dd3971ba
806012103c7c4c96ee56e4c0c0e0936398f49b4b98a33abad058e0b1fc96f0b6f6cf681cffffffff
f0280a4bf070000000017a914afb334044626bfd07b836d1e768b5802e8d1d3908779a3d4f416010
0001976a9141f6f406e5982f8d45098a1206f615cc632c2067588ac00000000""",
        ],
        )


def test_mnemonic_prompt():
    """Check if --mnemonic-file not passed mnemonic is via prompt"""
    with mock.patch('garecovery.recoverycli.user_input') as user_input_:
        mnemonic = open(datafile('mnemonic_1.txt')).read()
        mnemonic = ' '.join(mnemonic.split())
        user_input_.return_value = mnemonic

        output = get_output([
            '2of2',
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
            ])
        except Exit:
            msg = 'argument --nlocktime-file is required'
            exit_.assert_called_once()
            assert exit_.call_args[0][0] == 2
            assert '--nlocktime-file' in exit_.call_args[0][1]
            assert 'required' in exit_.call_args[0][1]
