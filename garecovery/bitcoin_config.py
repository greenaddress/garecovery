import io
import os
import logging
import configparser


DEFAULT_CONFIG_FILENAME = {
    False: "~/.bitcoin/bitcoin.conf",
    True: "~/.elements/elements.conf",
}
DUMMY_SECTION = 'X'


class Config:
    """Parse bitcoin configuration file"""

    def __init__(self, config_filename=None, is_liquid=False):
        if config_filename is None:
            config_filename = os.path.expanduser(DEFAULT_CONFIG_FILENAME[is_liquid])

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
