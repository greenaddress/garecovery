import base64
import logging
import os
import socket

from . import bitcoin_config
from . import exceptions
from gaservices.utils import gacommon

import bitcoinrpc.authproxy


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


UNSUPPORTED_VERSION = """\
Bitcoin Core version too old, minimum supported version 0.16.0
"""


class Connection:

    @staticmethod
    def read_config(keys, options):
        config = bitcoin_config.Config(options.config_filename, gacommon.is_liquid(options.network))
        section = {
            'mainnet': 'main',
            'testnet': 'test',
            'liquid': 'liquidv1',
            'localtest-liquid': 'liquidregtest',  # this may vary though
        }[options.network]
        return {key: config.get_val(section, key) for key in keys}

    @staticmethod
    def get_http_auth_header(config, network):
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
                    'testnet': '~/.bitcoin/testnet3/.cookie',
                    'mainnet': '~/.bitcoin/.cookie',
                    'liquid': '~/.elements/liquidv1/.cookie',
                    'localtest-liquid': '~/.elements/elementsregtest/.cookie',
                }
                rpccookiefile = os.path.expanduser(default_rpc_cookies[network])
            logging.info('Reading bitcoin authentication cookie from "{}"'.format(rpccookiefile))
            auth_data = open(rpccookiefile, "r").read().strip().encode("ascii")

        return "Basic {}".format(base64.b64encode(auth_data).decode('utf-8'))

    def __getattr__(self, name):
        try:
            return getattr(self.rpc, name)
        except AttributeError:
            return None

    def __init__(self, args):
        # Read from rpc params from config file
        keys = ['rpcuser', 'rpcpassword', 'rpcconnect', 'rpcport', 'rpccookiefile', 'rpcwallet']
        config = Connection.read_config(keys, args)

        # Override with command line options
        for key in keys:
            override = getattr(args, key, None)
            if override is not None:
                # empty string is a valid rpcwallet value
                config[key] = override
        logging.debug('config: {}'.format(config))

        # Default ports
        if config.get('rpcport', None) is None:
            default_rpc_ports = {
                'testnet': 18332,
                'mainnet': 8332,
                'liquid': 7041,
                'localtest-liquid': 7040,
            }
            config['rpcport'] = default_rpc_ports[args.network]
            logging.info('Defaulting rpc port to {}'.format(config['rpcport']))

        # connect to core
        try:
            try:
                http_auth_header = Connection.get_http_auth_header(config, args.network)
                hostname = config['rpcconnect']
                port = config['rpcport']
                wallet = config.get('rpcwallet')
            except KeyError as e:
                raise exceptions.BitcoinCoreConnectionError(MISSING_RPC_PARAM.format(e))

            logging.info('Connecting to bitcoin rpc {}:{}'.format(hostname, port))
            # Workaround for using authentication methods other than username/password
            # Passing x:y@ here as a hack because the authentication header is going to
            # be replaced anyway
            connstr = "http://x:y@{}:{}".format(hostname, port)
            if wallet is not None:
                connstr += f'/wallet/{wallet}'
            timeout = 60 * args.rpc_timeout_minutes
            self.rpc = AuthServiceProxy(connstr, http_auth_header, timeout=timeout)
            logging.info('HTTP timeout set to {}s'.format(timeout))

            logging.info('Calling getnetworkinfo to confirm connection and version')
            networkinfo = self.rpc.getnetworkinfo()
            if networkinfo["version"] < 160000:
                raise exceptions.BitcoinCoreConnectionError(UNSUPPORTED_VERSION)
            logging.info('Connected - getnetworkinfo successful')

        except socket.error as e:
            logging.warn(str(e))
            raise exceptions.BitcoinCoreConnectionError(CORE_CONNECT_ERR.format(connstr))
