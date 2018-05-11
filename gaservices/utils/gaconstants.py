""" Constant values for recovery/BTC """
import decimal
import sys

PY3 = sys.version_info.major > 2

SATOSHI_PER_BTC = decimal.Decimal(1e8)

MAX_BIP125_RBF_SEQUENCE = 0xfffffffd

# BIP32 hardened derivation flag
HARDENED = 0x80000000

P2PKH_MAINNET = 0x00
P2SH_MAINNET = 0x05

P2PKH_TESTNET = 0x6f
P2SH_TESTNET = 0xc4

ADDR_VERSIONS_MAINNET = [P2PKH_MAINNET, P2SH_MAINNET]
ADDR_VERSIONS_TESTNET = [P2PKH_TESTNET, P2SH_TESTNET]

def get_address_versions(is_testnet):
    return ADDR_VERSIONS_TESTNET if is_testnet else ADDR_VERSIONS_MAINNET

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
