import io
import os
import logging

try:
    # Python2
    import ConfigParser as configparser
except ImportError:
    # Python3
    import configparser


DEFAULT_CONFIG_FILENAME = "~/.bitcoin/bitcoin.conf"
DUMMY_SECTION = 'X'


class Config:
    """Parse bitcoin configuration file"""

    def __init__(self, config_filename=None):
        if config_filename is None:
            config_filename = os.path.expanduser(DEFAULT_CONFIG_FILENAME)

        self.config = configparser.ConfigParser()
        try:
            logging.info('Reading bitcoin config from {}'.format(config_filename))
            with open(config_filename) as config_file:
                # Using ConfigParser for this. ConfigParser requires that the
                # config file has 'sections', at least one, so inject a dummy
                # section 'X'
                content = u'[{}]'.format(DUMMY_SECTION) + config_file.read()
                self.config.readfp(io.StringIO(content))

        except IOError:
            logging.debug('Failed to open bitcoin config file {}'.format(config_filename))

    def get_val(self, key):
        if self.config.has_option('{}'.format(DUMMY_SECTION), key):
            val = self.config.get('{}'.format(DUMMY_SECTION), key)
            logging.debug('Read {} from config: {}'.format(key, val))
            return val
        else:
            return None
