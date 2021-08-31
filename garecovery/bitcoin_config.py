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

            for key in self.config.options(DUMMY_SECTION):
                key_split = key.split('.')
                if len(key_split) == 2:
                    # Move prefixed entries to their sections
                    prefix, actual_key = key_split
                    self.config[prefix][actual_key] = self.config[DUMMY_SECTION].pop(key)
                else:
                    # Set unprefixed entries as default values
                    self.config['DEFAULT'][key] = self.config[DUMMY_SECTION].pop(key)

        except IOError:
            logging.debug('Failed to open bitcoin config file {}'.format(config_filename))

    def get_val(self, section, key):
        if self.config.has_option(section, key):
            val = self.config.get(section, key)
            logging.debug('Read {} from config: {}'.format(key, val))
            return val
        else:
            return None
