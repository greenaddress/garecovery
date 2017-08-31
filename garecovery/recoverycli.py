import logging
import os
import sys

from wallycore import *

from . import clargs
from . import exceptions
from . import formatting

from .two_of_two import TwoOfTwo
from .two_of_three import TwoOfThree

import pycoin.networks.default

from . import monkeypatch_pycoin


# Python 2/3 compatibility
try:
    user_input = raw_input
except NameError:
    user_input = input


def seed_from_mnemonic(mnemonic_or_hex_seed):
    """Return seed, mnemonic given an input string

    mnemonic_or_hex_seed can either be:
    - A mnemonic
    - A hex seed, with an 'X' at the end, which needs to be stripped

    seed will always be returned, mnemonic may be None if a seed was passed
    """
    if mnemonic_or_hex_seed.endswith('X'):
        mnemonic = None
        seed = hex_to_bytes(mnemonic_or_hex_seed[:-1])
    else:
        mnemonic = mnemonic_or_hex_seed
        written, seed = bip39_mnemonic_to_seed512(mnemonic_or_hex_seed, None)
        assert written == BIP39_SEED_LEN_512

    assert len(seed) == BIP39_SEED_LEN_512
    return seed, mnemonic


def wallet_from_mnemonic(mnemonic_or_hex_seed, ver=BIP32_VER_MAIN_PRIVATE):
    """Generate a BIP32 HD Master Key (wallet) from a mnemonic phrase or a hex seed"""
    seed, mnemonic = seed_from_mnemonic(mnemonic_or_hex_seed)
    return bip32_key_from_seed(seed, ver, BIP32_FLAG_SKIP_HASH)


def get_mnemonic(args, attr='mnemonic_file', prompt='mnemonic/hex seed: '):
    """Get a mnemonic/hex_seed either from file or from the console"""
    filename = getattr(args, attr)
    if not filename:
        mnemonic = user_input(prompt)
    else:
        mnemonic = open(filename).read()
    return ' '.join(mnemonic.split())


def get_recovery_mnemonic(args):
    return get_mnemonic(args, 'recovery_mnemonic_file', 'recovery mnemonic/hex seed: ')


def get_recovery(options, mnemonic, seed):
    """Return an instance of either TwoOfTwo or TwoOfThree, depending on options"""
    if options.recovery_mode == '2of3':
        # Passing BIP32_VER_MAIN_PRIVATE although it may be on TEST. It doesn't make any difference
        # because they key is not going to be serialized
        wallet = bip32_key_from_seed(seed, BIP32_VER_MAIN_PRIVATE, BIP32_FLAG_SKIP_HASH)

        backup_wallet = None
        if not options.custom_xprv:
            recovery_mnemonic = get_recovery_mnemonic(options)
            backup_wallet = wallet_from_mnemonic(recovery_mnemonic)

        return TwoOfThree(mnemonic, wallet, backup_wallet, options.custom_xprv)
    else:
        return TwoOfTwo(mnemonic, seed, options.nlocktime_file)


def main(argv=None):
    clargs.set_args(argv or sys.argv)
    logging.basicConfig(level=clargs.args.loglevel)

    try:
        # Open the csv output file before doing anything else in case it fails
        # Do not overwrite the output file if it already exists
        output_filename = clargs.args.output_file
        if os.path.exists(output_filename):
            raise exceptions.OfileExistsError(
                'Output file "{}" already exists, refusing to overwrite. Either remove the '
                'existing file or pass -o to specify a different output file'
                .format(output_filename))

        with open(output_filename, "w") as ofile:

            mnemonic_or_hex_seed = get_mnemonic(clargs.args)
            seed, mnemonic = seed_from_mnemonic(mnemonic_or_hex_seed)

            recovery = get_recovery(clargs.args, mnemonic, seed)

            # Set the pycoin netcode
            netcode = 'XTN' if recovery.is_testnet else 'BTC'
            pycoin.networks.default.set_default_netcode(netcode)

            txs = recovery.get_transactions()
            formatting.write_summary(txs, sys.stdout)
            formatting.write_csv(txs, ofile)

        return 0

    except exceptions.GARecoveryError as e:
        print(e)
        return -1
