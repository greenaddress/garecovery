import logging
import os
import sys

import wallycore as wally

from gaservices.utils.gacommon import is_liquid
from . import clargs
from . import exceptions
from . import formatting
from .mnemonic import (check_mnemonic_or_hex_seed, _decrypt_mnemonic, seed_from_mnemonic,
                       wallet_from_mnemonic)

from .two_of_two import TwoOfTwo
from .two_of_two_csv import TwoOfTwoCSV
from .two_of_three import TwoOfThree
from .liquid_recovery import LiquidRecovery


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

    mnemonic = ' '.join(mnemonic.split())
    check_mnemonic_or_hex_seed(mnemonic)
    return mnemonic


def get_passphrase(args, file_attr='passphrase_file', prompt_attr='prompt_passphrase',
                   prompt='passphrase: '):
    """Get a passphrase either from file or from the console"""

    # strip any trailing newline character - but not whitespace in general (as
    # a cunning passphrase may contain trailing space characters)
    filename = getattr(args, file_attr)
    passphrase = open(filename).read().rstrip(os.linesep) if filename else None
    prompt_for_passphrase = getattr(args, prompt_attr)

    if prompt_for_passphrase:
        assert not passphrase
        passphrase = user_input(prompt)

    return passphrase


def get_recovery_mnemonic(args):
    return get_mnemonic(args, 'recovery_mnemonic_file', 'recovery mnemonic/hex seed: ')


# This call accepts (optional) mnemonic but does not include any bip39 passphrase.
# The mnemonic is only used to derive a potential gait path for legacy wallets,
# and at that time we did not support bip39 passphrase, so any wallets that have
# a gait path derived from mnemonic would not have a passphrase.
# See also: gait_path_from_mnemonic()
def get_recovery(options, mnemonic, seed):
    """Return an instance of either TwoOfTwo, TwoOfThree or LiquidRecovery, depending on options"""
    if options.recovery_mode == 'csv':
        if is_liquid(options.network):
            # Liquid does not need mnemonic, as gait path always from seed
            return LiquidRecovery(seed)
        raise exceptions.InvalidNetwork(
            'recovery method {} is not available for this network'.format(options.recovery_mode))
    elif options.recovery_mode == '2of3':
        backup_wallet = None
        if not options.custom_xprv:
            # Note: passphrase does not apply to backup key
            recovery_mnemonic = get_recovery_mnemonic(options)
            backup_wallet = wallet_from_mnemonic(recovery_mnemonic, passphrase=None)

        return TwoOfThree(mnemonic, seed, backup_wallet, options.custom_xprv)
    elif options.recovery_mode == '2of2':
        return TwoOfTwo(mnemonic, seed, options.nlocktime_file)
    else:
        return TwoOfTwoCSV(mnemonic, seed)


def main(argv=None, is_liquid=False):
    wally.init(0)
    wally.secp_randomize(os.urandom(wally.WALLY_SECP_RANDOMIZE_LEN))

    clargs.set_args(argv or sys.argv, is_liquid)
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
            passphrase = get_passphrase(clargs.args)
            seed, mnemonic = seed_from_mnemonic(mnemonic_or_hex_seed, passphrase)

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
