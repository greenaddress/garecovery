import struct

import wallycore as wally

from . import exceptions

HARDENED = 0x80000000

ga_key_data = {
    'main': {
        'chaincode': 'e9a563d68686999af372a33157209c6860fe79197a4dafd9ec1dbaa49523351d',
        'pubkey': '0322c5f5c9c4b9d1c3e22ca995e200d724c2d7d8b6953f7b38fddf9296053c961f',
    },
    'test': {
        'chaincode': 'b60befcc619bb1c212732770fe181f2f1aa824ab89f8aab49f2e13e3a56f0f04',
        'pubkey': '036307e560072ed6ce0aa5465534fb5c258a2ccfbc257f369e8e7a181b16d897b3',
    },
}


def get_bip32_pubkey(chaincode, key, testnet):
    """Return a bip32 public key which can be either mainnet or testnet"""
    ver = wally.BIP32_VER_TEST_PUBLIC if testnet else wally.BIP32_VER_MAIN_PUBLIC
    public_key = key
    private_key = None
    return wally.bip32_key_init(ver, 0, 0, chaincode, public_key, private_key, None, None)


def get_ga_root_key(testnet):
    """Return the GreenAddress root public key for the given network, or as set by options"""
    net = 'test' if testnet else 'main'
    return get_bip32_pubkey(
        wally.hex_to_bytes(ga_key_data[net]['chaincode']),
        wally.hex_to_bytes(ga_key_data[net]['pubkey']),
        testnet,
    )


def derive_ga_xpub(gait_path, subaccount, testnet):
    """Derive a GreenAddress extended public key"""
    ga_root_key = get_ga_root_key(testnet)
    if subaccount is not None:
        branch = 3
        ga_path = [branch] + gait_path + [subaccount]
    else:
        branch = 1
        ga_path = [branch] + gait_path
    flags = wally.BIP32_FLAG_KEY_PUBLIC | wally.BIP32_FLAG_SKIP_HASH
    return wally.bip32_key_from_parent_path(ga_root_key, ga_path, flags)


def get_gait_path(path_input):
    """Return the gait path given an input string

    The input string depends on the derivation mechanism
    """
    GA_KEY = bytearray('GreenAddress.it HD wallet path', 'ascii')
    path = wally.hmac_sha512(GA_KEY, path_input)
    return [struct.unpack('!H',
            path[i * 2:(i + 1) * 2])[0] for i in range(len(path) // 2)]


def gait_path_from_mnemonic(mnemonic):
    """Get the standard path for deriving the GreenAddress xpub from the mnemonic"""
    GA_PATH = bytearray('greenaddress_path', 'ascii')
    derived512 = wally.pbkdf2_hmac_sha512(bytearray(mnemonic, "ascii"), GA_PATH, 0, 2048)
    return get_gait_path(derived512)


def gait_paths_from_seed(seed):
    """Get the paths for deriving the GreenAddress xpubs from a hex seed, rather than mnemonic

    This is an alternative derivation path used with hardware wallets where the mnemonic may not
    be available. It is based on a hardened public key derived from the backed up hw wallet seed.

    Returns two possible paths corresponding to two different client implementations.
    """
    assert len(seed) == wally.BIP39_SEED_LEN_512

    # Passing version=BIP32_VER_MAIN_PRIVATE here although it may be either MAIN or TEST
    # This version indicator only matters if you serialize the key
    version = wally.BIP32_VER_MAIN_PRIVATE
    root_key = wally.bip32_key_from_seed(seed, version, wally.BIP32_FLAG_SKIP_HASH)

    # path = m/18241'
    # 18241 = 0x4741 = 'GA'
    flags = wally.BIP32_FLAG_KEY_PUBLIC | wally.BIP32_FLAG_SKIP_HASH
    derived_public_key = wally.bip32_key_from_parent_path(root_key, [HARDENED | 18241], flags)
    chain_code = wally.bip32_key_get_chain_code(derived_public_key)
    pub_key = wally.bip32_key_get_pub_key(derived_public_key)

    # For historic reasons some old clients use a hexlified input path here - generate both
    path_input = chain_code + pub_key
    path_input_hex = bytearray(wally.hex_from_bytes(chain_code + pub_key), 'ascii')
    return [get_gait_path(path_input) for path_input in [path_input, path_input_hex]]


def xpubs_from_mnemonic(mnemonic, subaccount, testnet):
    """Derive GreenAddress xpubs from a mnemonic"""
    if mnemonic is None:
        msg = 'You must either pass --ga-xpub or a mnemonic (not hex seed)'
        raise exceptions.NeedMnemonicOrGaXPub(msg)
    gait_path = gait_path_from_mnemonic(mnemonic)

    # Include the new derivations for newer wallets and hardware mnemonics
    written, seed = wally.bip39_mnemonic_to_seed512(mnemonic, None)
    assert written == wally.BIP39_SEED_LEN_512

    gait_paths = [gait_path] + gait_paths_from_seed(seed)
    return [derive_ga_xpub(gait_path, subaccount, testnet) for gait_path in gait_paths]


def xpubs_from_seed(seed, subaccount, testnet):
    """Derive GreenAddress xpubs from a hex seed"""
    gait_paths = gait_paths_from_seed(seed)
    return [derive_ga_xpub(gait_path, subaccount, testnet) for gait_path in gait_paths]
