""" Constant values for recovery/BTC """
import decimal
import sys
import wallycore as wally

PY3 = sys.version_info.major > 2

SATOSHI_PER_BTC = decimal.Decimal(1e8)

DUST_SATOSHI = 546

MAX_BIP125_RBF_SEQUENCE = 0xfffffffd

# BIP32 hardened derivation flag
HARDENED = 0x80000000

SUPPORTED_NETWORKS = {
    False: ['mainnet', 'testnet'],
    True: ['liquid', 'testnet-liquid', 'localtest-liquid']
}

P2PKH_MAINNET = wally.WALLY_ADDRESS_VERSION_P2PKH_MAINNET
P2SH_MAINNET = wally.WALLY_ADDRESS_VERSION_P2SH_MAINNET

P2PKH_TESTNET = wally.WALLY_ADDRESS_VERSION_P2PKH_TESTNET
P2SH_TESTNET = wally.WALLY_ADDRESS_VERSION_P2SH_TESTNET

P2PKH_LIQUID = wally.WALLY_ADDRESS_VERSION_P2PKH_LIQUID
P2SH_LIQUID = wally.WALLY_ADDRESS_VERSION_P2SH_LIQUID

P2PKH_LIQUID_TESTNET = wally.WALLY_ADDRESS_VERSION_P2PKH_LIQUID_TESTNET
P2SH_LIQUID_TESTNET = wally.WALLY_ADDRESS_VERSION_P2SH_LIQUID_TESTNET

P2PKH_LIQUID_REGTEST = wally.WALLY_ADDRESS_VERSION_P2PKH_LIQUID_REGTEST
P2SH_LIQUID_REGTEST = wally.WALLY_ADDRESS_VERSION_P2SH_LIQUID_REGTEST

ADDR_VERSIONS_MAINNET = [P2PKH_MAINNET, P2SH_MAINNET]
ADDR_VERSIONS_TESTNET = [P2PKH_TESTNET, P2SH_TESTNET]
ADDR_VERSIONS_LIQUID = [P2PKH_LIQUID, P2SH_LIQUID]
ADDR_VERSIONS_LIQUID_TESTNET = [P2PKH_LIQUID_TESTNET, P2SH_LIQUID_TESTNET]
ADDR_VERSIONS_LIQUID_REGTEST = [P2PKH_LIQUID_REGTEST, P2SH_LIQUID_REGTEST]

ADDR_FAMILY_MAINNET = 'bc'
ADDR_FAMILY_TESTNET = 'tb'
ADDR_FAMILY_LIQUID = 'lq'
ADDR_FAMILY_LIQUID_TESTNET = 'tlq'
ADDR_FAMILY_LIQUID_REGTEST = 'el'

CA_PREFIX = {
    'liquid': wally.WALLY_CA_PREFIX_LIQUID,
    'localtest-liquid': wally.WALLY_CA_PREFIX_LIQUID_REGTEST,
    'testnet-liquid': wally.WALLY_CA_PREFIX_LIQUID_TESTNET,
}

CSV_BUCKETS = {
    'liquid': [65535],
    'testnet-liquid': [1440, 65535],
    'localtest-liquid': [144, 1440, 65535],  # 144 for testing purposes
    'testnet': [144, 4320, 51840],
    'mainnet': [25920, 51840, 65535],
}

EMPTY_TX_SIZE = 106  # 0 inputs 1 p2wsh (longest) output
INPUT_SIZE = 159

# TODO: correctly estimate transaction vsize
# The following values overestimate the impact of adding an input or output to the transaction vsize, in order to
# produce a valid feerate. A temporary solution can be tweaking such values in order to match the desired feerate.
LIQUID_EMPTY_TX_SIZE = 40
LIQUID_INPUT_SIZE = 150
LIQUID_OUTPUT_SIZE = 1200


def get_address_versions(network):
    return {
        'testnet': ADDR_VERSIONS_TESTNET,
        'mainnet': ADDR_VERSIONS_MAINNET,
        'liquid': ADDR_VERSIONS_LIQUID,
        'testnet-liquid': ADDR_VERSIONS_LIQUID_TESTNET,
        'localtest-liquid': ADDR_VERSIONS_LIQUID_REGTEST,
    }[network]

def get_address_family(network):
    return {
        'testnet': ADDR_FAMILY_TESTNET,
        'mainnet': ADDR_FAMILY_MAINNET,
        'liquid': ADDR_FAMILY_LIQUID,
        'testnet-liquid': ADDR_FAMILY_LIQUID_TESTNET,
        'localtest-liquid': ADDR_FAMILY_LIQUID_REGTEST,
    }[network]

# GreenAddress script type for standard p2sh multisig UTXOs
P2SH_FORTIFIED_OUT = 10
# GreenAddress script type for p2sh-p2wsh multisig segwit UTXOs
P2SH_P2WSH_FORTIFIED_OUT = 14

# GreenAddress xpubs for mainnet/testnet
GA_KEY_DATA_MAINNET = {
    'chaincode': 'e9a563d68686999af372a33157209c6860fe79197a4dafd9ec1dbaa49523351d',
    'pubkey': '0322c5f5c9c4b9d1c3e22ca995e200d724c2d7d8b6953f7b38fddf9296053c961f',
}

GA_KEY_DATA_TESTNET = {
    'chaincode': 'b60befcc619bb1c212732770fe181f2f1aa824ab89f8aab49f2e13e3a56f0f04',
    'pubkey': '036307e560072ed6ce0aa5465534fb5c258a2ccfbc257f369e8e7a181b16d897b3',
}

GA_KEY_DATA_LIQUID = {
    'chaincode': '02721cc509aa0c2f4a90628e9da0391b196abeabc6393ed4789dd6222c43c489',
    'pubkey': '02c408c3bb8a3d526103fb93246f54897bdd997904d3e18295b49a26965cb41b7f'
}

GA_KEY_DATA_LIQUID_TESTNET = {
    'chaincode': 'c660eec6d9c536f4121854146da22e02d4c91d72af004d41729b9a592f0788e5',
    'pubkey': '02c47d84a5b256ee3c29df89642d14b6ed73d17a2b8af0aca18f6f1900f1633533'
}

GA_KEY_DATA_LIQUID_REGTEST = GA_KEY_DATA_TESTNET

def get_ga_key_data(network):
    return {
        'testnet': GA_KEY_DATA_TESTNET,
        'mainnet': GA_KEY_DATA_MAINNET,
        'liquid': GA_KEY_DATA_LIQUID,
        'testnet-liquid': GA_KEY_DATA_LIQUID_TESTNET,
        'localtest-liquid': GA_KEY_DATA_LIQUID_REGTEST,
    }[network]
