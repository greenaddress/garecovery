#!/usr/bin/env python3

import mock

import garecovery.bitcoin_config
from garecovery.clargs import DEFAULT_SUBACCOUNT_SEARCH_DEPTH
from .util import AuthServiceProxy, datafile, get_output, raise_IOError, verify_txs


garecovery.bitcoin_config.open = raise_IOError
sub_depth = DEFAULT_SUBACCOUNT_SEARCH_DEPTH
key_depth = 20
destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'


def _verify_nlocktime(mnemonic_filename, nlocktimes_filename, expect_witness, utxos):
    output = get_output([
        '--mnemonic-file={}'.format(datafile(mnemonic_filename)),
        '2of2',
        '--network=testnet',
        '--nlocktime-file={}'.format(datafile(nlocktimes_filename)),
    ])

    outputs = [output.split() for output in output.strip().split("\n")]
    txs = [tx for tx, _ in outputs]

    verify_txs(txs, utxos, expect_witness)


def test_nlocktime_verify_segwit():
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

    _verify_nlocktime(
        'mnemonic_5.txt',
        'nlocktimes_2.zip',
        True,
        utxos,
        )


def test_nlocktime_verify_nonsegwit():
    _verify_nlocktime(
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


def _verify_scan(mnemonic_filename, recovery_mnemonic_filename, utxos, expect_witness):
    """Verify tx signatures"""
    destination_address = 'mrZ98U4Vibu9hBMdcdrY5sXpC9Grr3Whpx'
    output = get_output([
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '--mnemonic-file={}'.format(datafile(mnemonic_filename)),
        '2of3',
        '--network=testnet',
        '--key-search-depth={}'.format(key_depth),
        '--search-subaccounts={}'.format(sub_depth),
        '--recovery-mnemonic-file={}'.format(datafile(recovery_mnemonic_filename)),
        '--destination-address={}'.format(destination_address),
    ])

    txs = [output for output in output.strip().split("\n")]
    assert len(txs) == 1
    verify_txs(txs, utxos, expect_witness)


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_scan_verify_nonsegwit(mock_bitcoincore):
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

    _verify_scan(
        'mnemonic_6.txt',
        'mnemonic_7.txt',
        utxos,
        False,
    )


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_scan_verify_segwit(mock_bitcoincore):
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

    _verify_scan(
        'mnemonic_8.txt',
        'mnemonic_9.txt',
        utxos,
        True,
    )
