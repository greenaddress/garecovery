import base64
import logging
import os
import socket

from . import bitcoin_config
from . import exceptions

import bitcoinrpc.authproxy

import pycoin.networks.default


class AuthServiceProxy(bitcoinrpc.authproxy.AuthServiceProxy):
    """Part of workaround for inflexible authentication

    A subclass of bitcoinrpc.authproxy.AuthServiceProxy which forcefully overrides the http
    authentication header
    """

    def __init__(self, connstr, http_auth_header, timeout):
        bitcoinrpc.authproxy.AuthServiceProxy.__init__(self, connstr, timeout=timeout)
        self.http_auth_header = http_auth_header

    def __getattr__(self, name):
        # Whenever __getattr__ is called on bitcoinrpc.authproxy.AuthServiceProxy it spawns a new
        # instance of AuthServiceProxy and derives the auth header from the url from scratch, so to
        # override it it has to be done every time here
        rpc = super(AuthServiceProxy, self).__getattr__(name)
        rpc._AuthServiceProxy__auth_header = self.http_auth_header
        return rpc

    def batch_(self, requests):
        return self.__getattr__("batch_").batch_(requests)

CORE_CONNECT_ERR = """\
Failed to connect to core daemon {}

Please ensure bitcoind is installed and running and
that the rpc connection parameters are correct
"""


MISSING_RPC_PARAM = """\
RPC parameter {} not found in config file or command line arguments
"""


class Connection:

    @staticmethod
    def read_config(keys, options):
        config = bitcoin_config.Config(options.config_filename)
        return {key: config.get_val(key) for key in keys}

    @staticmethod
    def get_http_auth_header(config, testnet):
        """Get HTTP authentication header

        Authentication is basic HTTP authentication.

        If rpcpassword is set then the data is rpcuser:rpcpassword
        If rpcpassword is not set then the data is read verbatim from the rpccookiefile
        """
        rpcpassword = config.get('rpcpassword', None)
        if rpcpassword:
            auth_data = '{}:{}'.format(config['rpcuser'], rpcpassword).encode('utf-8')
        else:
            rpccookiefile = config['rpccookiefile']
            if rpccookiefile is None:
                default_rpc_cookies = {
                    True: '~/.bitcoin/testnet3/.cookie',
                    False: '~/.bitcoin/.cookie',
                }
                rpccookiefile = os.path.expanduser(default_rpc_cookies[testnet])
            logging.info('Reading bitcoin authentication cookie from "{}"'.format(rpccookiefile))
            auth_data = open(rpccookiefile, "r").read().strip().encode("ascii")

        return "Basic {}".format(base64.b64encode(auth_data))

    def __getattr__(self, name):
        try:
            return getattr(self.rpc, name)
        except:
            return None

    def __init__(self, options):
        # FIXME: This is not the right place for this
        testnet = pycoin.networks.default.get_current_netcode() == 'XTN'

        # Read from rpc params from config file
        keys = ['rpcuser', 'rpcpassword', 'rpcconnect', 'rpcport', 'rpccookiefile']
        config = Connection.read_config(keys, options)

        # Override with command line options
        for key in keys:
            override = getattr(options, key, None)
            if override:
                config[key] = override
        logging.debug('config: {}'.format(config))

        # Default ports
        if config.get('rpcport', None) is None:
            default_rpc_ports = {
                True: 18332,
                False: 8332,
            }
            config['rpcport'] = default_rpc_ports[testnet]
            logging.info('Defaulting rpc port to {}'.format(config['rpcport']))

        # connect to core
        try:
            try:
                http_auth_header = Connection.get_http_auth_header(config, testnet)
                hostname = config['rpcconnect']
                port = config['rpcport']
            except KeyError as e:
                raise exceptions.BitcoinCoreConnectionError(MISSING_RPC_PARAM.format(e))

            logging.info('Connecting to bitcoin rpc {}:{}'.format(hostname, port))
            # Workaround for using authentication methods other than username/password
            # Passing x:y@ here as a hack because the authentication header is going to
            # be replaced anyway
            connstr = "http://x:y@{}:{}".format(hostname, port)
            timeout = 60*options.rpc_timeout_minutes
            self.rpc = AuthServiceProxy(connstr, http_auth_header, timeout=timeout)
            logging.info('HTTP timeout set to {}s'.format(timeout))

            logging.info('Calling getblockcount to confirm connection')
            blockcount = self.rpc.getblockcount()
            logging.info('Connected - getblockcount returned {}'.format(blockcount))

        except socket.error as e:
            logging.warn(str(e))
            raise exceptions.BitcoinCoreConnectionError(CORE_CONNECT_ERR.format(connstr))
