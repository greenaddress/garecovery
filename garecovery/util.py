import logging

from . import bitcoincore
from . import clargs


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
