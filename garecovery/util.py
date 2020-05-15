import decimal
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


def get_default_feerate():
    """Get a value for default feerate.

    On testnet only it is possible to pass --default-feerate as an option. On mainnet this is
    not supported as it is too error prone.
    """
    if clargs.args.default_feerate is None:
        msg = 'Unable to get fee rate from core, you must pass --default-feerate'
        raise exceptions.NoFeeRate(msg)

    fee_satoshi_byte = decimal.Decimal(clargs.args.default_feerate)
    return fee_satoshi_byte


def get_feerate():
    """Return the required fee rate in satoshis per byte"""
    logging.debug("Connecting to bitcoinrpc to get feerate")
    core = bitcoincore.Connection(clargs.args)

    blocks = clargs.args.fee_estimate_blocks

    estimate = core.estimatesmartfee(blocks)
    if 'errors' in estimate:
        fee_satoshi_byte = get_default_feerate()
    else:
        fee_btc_kb = estimate['feerate']
        fee_satoshi_kb = fee_btc_kb * gaconstants.SATOSHI_PER_BTC
        fee_satoshi_byte = round(fee_satoshi_kb / 1000)

        logging.debug('feerate = {} BTC/kb'.format(fee_btc_kb))
        logging.debug('feerate = {} satoshis/kb'.format(fee_satoshi_kb))

    logging.info('Fee estimate for confirmation in {} blocks is '
                 '{} satoshis/byte'.format(blocks, fee_satoshi_byte))

    return fee_satoshi_byte


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


def network_from_address(address):
    is_base58_address, decoded = decode_base58_address(address)
    if is_base58_address:
        return 'testnet' if decoded[0] in gaconstants.ADDR_VERSIONS_TESTNET else 'mainnet'
    elif decode_segwit_address(address)[0]:
        return 'testnet' if address[:2] == gaconstants.ADDR_FAMILY_TESTNET else 'mainnet'
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
