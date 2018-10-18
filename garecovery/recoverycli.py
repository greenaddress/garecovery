import logging
import os
import sys

import wallycore as wally

from . import clargs
from . import exceptions
from . import formatting
from .mnemonic import _decrypt_mnemonic, seed_from_mnemonic, wallet_from_mnemonic

from .two_of_two import TwoOfTwo
from .two_of_three import TwoOfThree


# Python 2/3 compatibility
try:
    user_input = raw_input
except NameError:
    user_input = input


def get_mnemonic(args, attr='mnemonic_file', prompt='mnemonic/hex seed: '):
    """Get a mnemonic/hex_seed either from file or from the console"""
    filename = getattr(args, attr)
    if not filename:
        mnemonic = user_input(prompt)
    else:
        mnemonic = open(filename).read()

    if len(mnemonic.split()) == 27:
        # encrypted mnemonic
        password = user_input('mnemonic password: ')
        return _decrypt_mnemonic(mnemonic, password)

    return ' '.join(mnemonic.split())


def get_recovery_mnemonic(args):
    return get_mnemonic(args, 'recovery_mnemonic_file', 'recovery mnemonic/hex seed: ')


def get_recovery(options, mnemonic, seed):
    """Return an instance of either TwoOfTwo or TwoOfThree, depending on options"""
    if options.recovery_mode == '2of3':
        # Passing BIP32_VER_MAIN_PRIVATE although it may be on TEST. It doesn't make any difference
        # because they key is not going to be serialized
        version = wally.BIP32_VER_MAIN_PRIVATE
        wallet = wally.bip32_key_from_seed(seed, version, wally.BIP32_FLAG_SKIP_HASH)

        backup_wallet = None
        if not options.custom_xprv:
            recovery_mnemonic = get_recovery_mnemonic(options)
            backup_wallet = wallet_from_mnemonic(recovery_mnemonic)

        return TwoOfThree(mnemonic, wallet, backup_wallet, options.custom_xprv)
    else:
        return TwoOfTwo(mnemonic, seed, options.nlocktime_file)


def main(argv=None):
    wally.init(0)
    wally.secp_randomize(os.urandom(wally.WALLY_SECP_RANDOMIZE_LEN))

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

            txs = recovery.get_transactions()
            if clargs.args.show_summary:
                formatting.write_summary(txs, sys.stdout)
            formatting.write_csv(txs, ofile)

        wally.cleanup(0)
        return 0

    except exceptions.GARecoveryError as e:
        print(e)
        wally.cleanup(0)
        return -1
