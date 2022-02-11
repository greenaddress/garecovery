import struct

from gaservices.utils import gaconstants, b2h, h2b
import wallycore as wally

from . import exceptions


def get_bip32_pubkey(chaincode, key, network):
    """Return a bip32 public key for the given network"""
    ver = {
        'testnet': wally.BIP32_VER_TEST_PUBLIC,
        'mainnet': wally.BIP32_VER_MAIN_PUBLIC,
        'liquid': wally.BIP32_VER_MAIN_PUBLIC,
        'testnet-liquid': wally.BIP32_VER_TEST_PUBLIC,
        'localtest-liquid': wally.BIP32_VER_TEST_PUBLIC,
    }[network]
    public_key = key
    private_key = None
    return wally.bip32_key_init(ver, 0, 0, chaincode, public_key, private_key, None, None)


def get_ga_root_key(network):
    """Return the GreenAddress root public key for the given network, or as set by options"""
    key_data = gaconstants.get_ga_key_data(network)
    return get_bip32_pubkey(
        h2b(key_data['chaincode']),
        h2b(key_data['pubkey']),
        network
    )


def derive_ga_xpub(gait_path, subaccount, network):
    """Derive a GreenAddress extended public key"""
    ga_root_key = get_ga_root_key(network)
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


# This function does not include any bip39 passphrase - but that is ok as deriving gait-path from
# mnemonic is legacy, and at that time we did not support bip39 passphrase, so any wallets that have
# a gait path derived from mnemonic would not have a passphrase.
# See also: xpubs_from_mnemonic()
def gait_path_from_mnemonic(mnemonic):
    """Get the standard path for deriving the GreenAddress xpub from the mnemonic

    NOTE: this function does not include support for bip39 passphrase
    """
    GA_PATH = bytearray('greenaddress_path', 'ascii')
    derived512 = wally.pbkdf2_hmac_sha512(bytearray(mnemonic, "ascii"), GA_PATH, 0, 2048)
    return get_gait_path(derived512)


def gait_paths_from_seed(seed, latest_only=False):
    """Get the paths for deriving the GreenAddress xpubs from a hex seed, rather than mnemonic

    This is an alternative derivation path used with hardware wallets where the mnemonic may not
    be available. It is based on a hardened public key derived from the backed up hw wallet seed
    or on the master public key itself.

    Returns three possible paths corresponding to three different client implementations.
    """
    assert len(seed) == wally.BIP39_SEED_LEN_512

    # Passing version=BIP32_VER_MAIN_PRIVATE here although it may be either MAIN or TEST
    # This version indicator only matters if you serialize the key
    version = wally.BIP32_VER_MAIN_PRIVATE
    root_key = wally.bip32_key_from_seed(seed, version, wally.BIP32_FLAG_SKIP_HASH)

    # path = m/18241'
    # 18241 = 0x4741 = 'GA'
    flags = wally.BIP32_FLAG_KEY_PUBLIC | wally.BIP32_FLAG_SKIP_HASH
    path = [gaconstants.HARDENED | 18241]
    derived_public_key = wally.bip32_key_from_parent_path(root_key, path, flags)
    chain_code = wally.bip32_key_get_chain_code(derived_public_key)
    pub_key = wally.bip32_key_get_pub_key(derived_public_key)

    # For historic reasons some old clients use a hexlified input path here - generate both
    path_input = chain_code + pub_key
    if latest_only:
        return get_gait_path(path_input)
    path_input_hex = bytearray(b2h(chain_code + pub_key), 'ascii')
    # Some clients use the master public key instead of one hardened derived from it
    chain_code_m = wally.bip32_key_get_chain_code(root_key)
    pub_key_m = wally.bip32_key_get_pub_key(root_key)
    path_input_m = chain_code_m + pub_key_m
    return [get_gait_path(path_input) for path_input in [path_input, path_input_hex, path_input_m]]


# This function does not include any bip39 passphrase - but that is ok as deriving gait-path from
# mnemonic is legacy, and at that time we did not support bip39 passphrase, so any wallets that have
# a gait path derived from mnemonic would not have a passphrase.
# See also: gait_path_from_mnemonic()
def xpubs_from_mnemonic(mnemonic, subaccount, network):
    """Derive GreenAddress xpubs from a mnemonic

    NOTE: this function does not include support for bip39 passphrase
    """
    gait_path = gait_path_from_mnemonic(mnemonic)
    return [derive_ga_xpub(gait_path, subaccount, network)]


def xpubs_from_seed(seed, subaccount, network):
    """Derive GreenAddress xpubs from a hex seed"""
    gait_paths = gait_paths_from_seed(seed)
    return [derive_ga_xpub(gait_path, subaccount, network) for gait_path in gait_paths]
