#!/usr/bin/env python3

import base64
import bitcoinrpc
import mock
import socket

import garecovery.two_of_three
from garecovery.clargs import DEFAULT_SUBACCOUNT_SEARCH_DEPTH
from .util import AuthServiceProxy, datafile, get_output, raise_IOError


garecovery.bitcoin_config.open = raise_IOError
sub_depth = DEFAULT_SUBACCOUNT_SEARCH_DEPTH
key_depth = 20
destination_address = 'mynHfTyTWyGGB76NBFbfUrTnn8YWQkTJVs'

# Patch open into bitcoincore to return a fixed config file
mock_read_data = """
rpcuser=rpcuser__
rpcpassword=rpcpassword__
rpcport=rpcport__
"""
bitcoincore_open = mock.mock_open(read_data=mock_read_data)
garecovery.two_of_three.bitcoincore.open = bitcoincore_open


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_importmulti_error(mock_bitcoincore):
    """Test handing of importmulti errors"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')
    mock_bitcoincore.return_value.importmulti = mock.Mock(return_value=[{'success': False}, ])

    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_2.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--network=testnet',
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_3.txt')),
        '--key-search-depth=5',
        '--search-subaccounts={}'.format(sub_depth),
        '--destination-address={}'.format(destination_address),
    ]
    output = get_output(args, expect_error=True)
    assert 'Unexpected result from importmulti' in output


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_missing_config_file_no_params(mock_bitcoincore):
    """Test missing config file"""
    with mock.patch('garecovery.two_of_three.bitcoincore.Connection.read_config'):
        @staticmethod
        def _read_config(keys, options):
            return {}
        garecovery.two_of_three.bitcoincore.Connection.read_config = _read_config

        config_filename = '/non/existent/file'

        output = get_output([
            '--mnemonic-file={}'.format(datafile('mnemonic_2.txt')),
            '--config-filename={}'.format(config_filename),
            '2of3',
            '--network=testnet',
            '--recovery-mnemonic-file={}'.format(datafile('mnemonic_3.txt')),
            '--key-search-depth={}'.format(key_depth),
            '--search-subaccounts={}'.format(sub_depth),
            '--destination-address={}'.format(destination_address),
        ],
            expect_error=True)

        msg = "not found in config file"
        assert msg in output


def check_http_auth(HTTPConnection, args, hostname, port, timeout, auth_data):
    try:
        get_output(args, True)
    except bitcoinrpc.authproxy.JSONRPCException:
        # Expect the test to completely fail because HTTPConnection is a mock
        pass

    # However before failing it should have connected...
    assert HTTPConnection.call_args_list == [
        mock.call(hostname, port, timeout=timeout),
    ]

    # .. and attempted a POST with the correct basic auth header
    expected_auth = "Basic {}".format(base64.b64encode(auth_data).decode('utf-8'))
    request_calls = HTTPConnection.return_value.request.call_args_list
    assert request_calls[0][0][3]['Authorization'] == expected_auth


@mock.patch('bitcoinrpc.authproxy.httplib.HTTPConnection')
def test_authenticate_password(HTTPConnection):
    """Test rpcpassword/rpcuser authentication"""
    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_6.txt')),
        '--rpcuser=abc',
        '--rpcpassword=abc',
        '2of3',
        '--network=testnet',
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_7.txt')),
        '--key-search-depth={}'.format(key_depth),
        '--search-subaccounts={}'.format(sub_depth),
        '--destination-address={}'.format(destination_address),
    ]

    check_http_auth(HTTPConnection, args, '127.0.0.1', 18332, 3600, b'abc:abc')


@mock.patch('bitcoinrpc.authproxy.httplib.HTTPConnection')
def test_authenticate_cookiefile(HTTPConnection):
    """Test rpcpassword/rpcuser authentication"""
    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_6.txt')),
        '2of3',
        '--network=testnet',
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_7.txt')),
        '--key-search-depth={}'.format(key_depth),
        '--search-subaccounts={}'.format(sub_depth),
        '--destination-address={}'.format(destination_address),
    ]

    # Because of the way mock_read has been used to return a fixed string representing a config
    # file, reading the cookiefile will also return this config file, however for the purposes
    # of the unit test it doesn't matter
    cookie = mock_read_data.strip().encode("ascii")
    check_http_auth(HTTPConnection, args, '127.0.0.1', 18332, 3600, cookie)


def test_core_daemon_not_available():
    """Test core not available"""
    rpcuser = 'rpcuser__'
    rpcpassword = 'rpcpassword__'
    rpcconnect = 'rpcconnect__'
    rpcport = 'rpcport__'
    rpcwallet = ''
    rpctimeout = 123

    def no_core(connstr, http_auth_header, timeout):
        # Check that the connection string is formed correctly from
        # the passed args, but then refuse to connect
        # The x.y is part of a workaround for authentication via python-bitcoinrpc
        assert connstr == "http://x:y@{}:{}/wallet/{}".format(rpcconnect, rpcport, rpcwallet)
        assert timeout == rpctimeout*60
        raise socket.error('[Errno 111] Connection refused')

    with mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy', no_core):

        output = get_output([
            '--mnemonic-file={}'.format(datafile('mnemonic_2.txt')),
            '--rpcuser={}'.format(rpcuser),
            '--rpcpassword={}'.format(rpcpassword),
            '--rpcconnect={}'.format(rpcconnect),
            '--rpcport={}'.format(rpcport),
            '--rpcwallet={}'.format(rpcwallet),
            '--rpc-timeout-minutes={}'.format(rpctimeout),
            '2of3',
            '--network=testnet',
            '--recovery-mnemonic-file={}'.format(datafile('mnemonic_3.txt')),
            '--key-search-depth={}'.format(key_depth),
            '--search-subaccounts={}'.format(sub_depth),
            '--destination-address={}'.format(destination_address),
        ],
            expect_error=True)

        assert "Failed to connect" in output


@mock.patch('garecovery.two_of_three.bitcoincore.AuthServiceProxy')
def test_too_old_version(mock_bitcoincore):
    """Test handling of a too old version"""
    mock_bitcoincore.return_value = AuthServiceProxy('testnet_txs')
    mock_bitcoincore.return_value.getnetworkinfo = mock.Mock(return_value={'version': 159900})

    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_2.txt')),
        '2of3',
        '--network=testnet',
        '--recovery-mnemonic-file={}'.format(datafile('mnemonic_3.txt')),
        '--key-search-depth=5',
        '--search-subaccounts={}'.format(sub_depth),
        '--destination-address={}'.format(destination_address),
    ]

    output = get_output(args, expect_error=True)
    assert 'Bitcoin Core version too old, minimum supported version 0.16.0' in output


@mock.patch('garecovery.liquid_recovery.bitcoincore.AuthServiceProxy')
def test_too_old_version_liquid(mock_bitcoincore):
    """Test Liquid asset recovery"""
    mock_bitcoincore.return_value = AuthServiceProxy('liquid_txs', is_liquid=True)
    mock_bitcoincore.return_value.getnetworkinfo = mock.Mock(return_value={'version': 169900})

    args = [
        '--mnemonic-file={}'.format(datafile('mnemonic_1.txt')),
        'csv',
        '--network=localtest-liquid',
        '--search-subaccounts={}'.format(sub_depth),
    ]

    output = get_output(args, expect_error=True, is_liquid=True)
    assert 'Unsupported version' in output
