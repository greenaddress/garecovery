import logging
import os
import sys

import wallycore as wally

from . import clargs
from . import exceptions
from . import formatting

from .two_of_two import TwoOfTwo
from .two_of_three import TwoOfThree

import pycoin.networks.default


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
        seed = wally.hex_to_bytes(mnemonic_or_hex_seed[:-1])
    else:
        mnemonic = mnemonic_or_hex_seed
        written, seed = wally.bip39_mnemonic_to_seed512(mnemonic_or_hex_seed, None)
        assert written == wally.BIP39_SEED_LEN_512

    assert len(seed) == wally.BIP39_SEED_LEN_512
    return seed, mnemonic


def wallet_from_mnemonic(mnemonic_or_hex_seed, ver=wally.BIP32_VER_MAIN_PRIVATE):
    """Generate a BIP32 HD Master Key (wallet) from a mnemonic phrase or a hex seed"""
    seed, mnemonic = seed_from_mnemonic(mnemonic_or_hex_seed)
    return wally.bip32_key_from_seed(seed, ver, wally.BIP32_FLAG_SKIP_HASH)


def _decrypt_mnemonic(mnemonic, password):
    """Decrypt a 27 word encrypted mnemonic to a 24 word mnemonic"""
    mnemonic = ' '.join(mnemonic.split())
    entropy = bytearray(wally.BIP39_ENTROPY_LEN_288)
    assert wally.bip39_mnemonic_to_bytes(None, mnemonic, entropy) == len(entropy)
    salt, encrypted = entropy[32:], entropy[:32]
    derived = bytearray(64)
    wally.scrypt(password.encode('utf-8'), salt, 16384, 8, 8, derived)
    key, decrypted = derived[32:], bytearray(32)
    wally.aes(key, encrypted, wally.AES_FLAG_DECRYPT, decrypted)
    for i in range(len(decrypted)):
        decrypted[i] ^= derived[i]
    if wally.sha256d(decrypted)[:4] != salt:
        raise exceptions.InvalidMnemonicOrPasswordError('Incorrect password')
    return wally.bip39_mnemonic_from_bytes(None, decrypted)


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
            clargs.args.is_testnet = recovery.is_testnet

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
