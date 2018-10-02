import logging

from gaservices.utils import gacommon, gaconstants

import wallycore as wally

from . import bitcoincore
from . import clargs
from . import exceptions


def get_current_blockcount():
    option = clargs.args.current_blockcount
    if option:
        logging.debug('Returning option current_blockcount={}'.format(option))
        return option
    try:
        logging.debug('Attempting to connect to core to get current block count')
        core = bitcoincore.Connection(clargs.args)
        return core.getblockcount()
    except Exception as e:
        logging.debug('Error getting block count from core: {}'.format(str(e)))
        return None


def decode_base58_address(address):
    try:
        decoded = wally.base58check_to_bytes(address)
        return ((len(decoded) == (1 + wally.HASH160_LEN) and decoded[0] in
                 gaconstants.ADDR_VERSIONS_TESTNET + gaconstants.ADDR_VERSIONS_MAINNET),
                decoded)
    except ValueError:
        return False, None


def decode_segwit_address(address):
    try:
        decoded = wally.addr_segwit_to_bytes(address, address[:2], 0)
        return (address[:2] in (gaconstants.ADDR_FAMILY_TESTNET, gaconstants.ADDR_FAMILY_MAINNET),
                decoded)
    except ValueError:
        return False, None


def is_testnet_address(address):
    is_base58_address, decoded = decode_base58_address(address)
    if is_base58_address:
        return decoded[0] in gaconstants.ADDR_VERSIONS_TESTNET
    elif decode_segwit_address(address)[0]:
        return address[:2] == gaconstants.ADDR_FAMILY_TESTNET
    raise exceptions.InvalidDestinationAddressError('Invalid address')


def scriptpubkey_from_address(address):
    is_base58_address, decoded = decode_base58_address(address)
    if is_base58_address:
        if decoded[0] in (gaconstants.P2PKH_TESTNET, gaconstants.P2PKH_MAINNET):
            return wally.scriptpubkey_p2pkh_from_bytes(decoded[1:], 0)
        elif decoded[0] in(gaconstants.P2SH_TESTNET, gaconstants.P2SH_MAINNET):
            return wally.scriptpubkey_p2sh_from_bytes(decoded[1:], 0)
    is_segwit_address, decoded = decode_segwit_address(address)
    if is_segwit_address:
        return decoded
    raise exceptions.InvalidDestinationAddressError('Invalid address')
