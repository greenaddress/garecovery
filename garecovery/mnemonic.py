import wallycore as wally

from . import exceptions


wordlist_ = wally.bip39_get_wordlist('en')
wordlist = [wally.bip39_get_word(wordlist_, i) for i in range(2048)]


def seed_from_mnemonic(mnemonic_or_hex_seed):
    """Return seed, mnemonic given an input string

    mnemonic_or_hex_seed can either be:
    - A mnemonic
    - A hex seed, with an 'X' at the end, which needs to be stripped

    seed will always be returned, mnemonic may be None if a seed was passed
    """
    if mnemonic_or_hex_seed.endswith('X'):
        mnemonic = None
        seed = wally.hex_to_bytes(mnemonic_or_hex_seed[:-1])
    else:
        mnemonic = mnemonic_or_hex_seed
        written, seed = wally.bip39_mnemonic_to_seed512(mnemonic_or_hex_seed, None)
        assert written == wally.BIP39_SEED_LEN_512

    assert len(seed) == wally.BIP39_SEED_LEN_512
    return seed, mnemonic


def wallet_from_mnemonic(mnemonic_or_hex_seed, ver=wally.BIP32_VER_MAIN_PRIVATE):
    """Generate a BIP32 HD Master Key (wallet) from a mnemonic phrase or a hex seed"""
    seed, mnemonic = seed_from_mnemonic(mnemonic_or_hex_seed)
    return wally.bip32_key_from_seed(seed, ver, wally.BIP32_FLAG_SKIP_HASH)


def _decrypt_mnemonic(mnemonic, password):
    """Decrypt a 27 word encrypted mnemonic to a 24 word mnemonic"""
    mnemonic = ' '.join(mnemonic.split())
    entropy = bytearray(wally.BIP39_ENTROPY_LEN_288)
    assert wally.bip39_mnemonic_to_bytes(None, mnemonic, entropy) == len(entropy)
    salt, encrypted = entropy[32:], entropy[:32]
    derived = bytearray(64)
    wally.scrypt(password.encode('utf-8'), salt, 16384, 8, 8, derived)
    key, decrypted = derived[32:], bytearray(32)
    wally.aes(key, encrypted, wally.AES_FLAG_DECRYPT, decrypted)
    for i in range(len(decrypted)):
        decrypted[i] ^= derived[i]
    if wally.sha256d(decrypted)[:4] != salt:
        raise exceptions.InvalidMnemonicOrPasswordError('Incorrect password')
    return wally.bip39_mnemonic_from_bytes(None, decrypted)


def check_mnemonic_or_hex_seed(mnemonic):
    """Raise an error if mnemonic/hex seed is invalid"""
    if ' ' not in mnemonic:
        if mnemonic.endswith('X'):
            # mnemonic is the hex seed
            return
        msg = 'Mnemonic words must be separated by spaces, hex seed must end with X'
        raise exceptions.InvalidMnemonicOrPasswordError(msg)

    for word in mnemonic.split():
        if word not in wordlist:
            msg = 'Invalid word: {}'.format(word)
            raise exceptions.InvalidMnemonicOrPasswordError(msg)

    try:
        wally.bip39_mnemonic_validate(None, mnemonic)
    except ValueError:
        raise exceptions.InvalidMnemonicOrPasswordError('Invalid mnemonic checksum')
