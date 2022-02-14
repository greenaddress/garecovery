from garecovery.exceptions import InvalidPrivateKey, InvalidPublicKey

import wallycore as wally


class ECKey(object):
    """Elliptic Curve key"""

    def __init__(self):
        self.__prv = None
        self.__pub = None

    @property
    def prv(self):
        return self.__prv

    @prv.setter
    def prv(self, prv):
        try:
            wally.ec_private_key_verify(prv)
        except ValueError:
            raise InvalidPrivateKey

        self.__prv = prv
        self.__pub = wally.ec_public_key_from_private_key(prv)

    @property
    def pub(self):
        return self.__pub

    @pub.setter
    def pub(self, pub):
        try:
            wally.ec_public_key_verify(pub)
        except ValueError:
            raise InvalidPublicKey
        if self.prv is not None:
            raise ValueError('Cannot set public key if private is already set')

        self.__pub = pub

    def sign_compact(self, h):
        """Produce a compact signature for (hashed) message h"""
        if self.prv is None:
            raise ValueError('Missing private key')

        return wally.ec_sig_from_bytes(self.prv, h, wally.EC_FLAG_ECDSA | wally.EC_FLAG_GRIND_R)

    def sign(self, h):
        """Produce a DER signature for (hashed) message h"""
        return wally.ec_sig_to_der(self.sign_compact(h))

    def verify_compact(self, h, sig):
        """Verify a compact signature"""
        if self.pub is None:
            raise ValueError('Missing public key')

        try:
            wally.ec_sig_verify(self.pub, h, wally.EC_FLAG_ECDSA, sig)
        except ValueError:
            return False
        return True

    def verify(self, h, sig):
        """Verify a DER signature"""
        try:
            sig_compact = wally.ec_sig_from_der(sig)
        except ValueError:
            return False
        return self.verify_compact(h, sig_compact)


class PubKey(bytes):
    """Public key"""

    def __new__(cls, buf, eckey=None):
        self = super(PubKey, cls).__new__(cls, buf)
        if eckey is None:
            eckey = ECKey()
        eckey.pub = buf
        self.eckey = eckey
        return self

    def verify_compact(self, h, sig):
        """Verify a compact signature"""
        return self.eckey.verify_compact(h, sig)

    def verify(self, h, sig):
        """Verify a DER signature"""
        return self.eckey.verify(h, sig)


class Bip32Key(object):
    """BIP32 key"""

    def __init__(self, extkey=None):
        self.extkey = extkey
        # TODO: handle missing private key

    @classmethod
    def from_b58(cls, b58):
        """Create a bip32 key from a base58 string"""
        extkey = wally.bip32_key_from_base58(b58)
        return cls(extkey)

    @classmethod
    def from_seed(cls, seed, is_testnet=False):
        """Create a bip32 key from a 128, 256, or 512 bit seed"""
        version = {True: wally.BIP32_VER_TEST_PRIVATE,
                   False: wally.BIP32_VER_MAIN_PRIVATE}[is_testnet]
        extkey = wally.bip32_key_from_seed(seed, version, wally.BIP32_FLAG_SKIP_HASH)
        return cls(extkey)

    @property
    def xprv(self):
        return wally.bip32_key_to_base58(self.extkey, wally.BIP32_FLAG_KEY_PRIVATE)

    @property
    def xpub(self):
        return wally.bip32_key_to_base58(self.extkey, wally.BIP32_FLAG_KEY_PUBLIC)

    @property
    def prv(self):
        return wally.bip32_key_get_priv_key(self.extkey)

    @property
    def pub(self):
        return wally.bip32_key_get_pub_key(self.extkey)

    @property
    def prvkey(self):
        k = ECKey()
        k.prv = self.prv
        return k

    @property
    def pubkey(self):
        return PubKey(self.pub)

    def _derive(self, path, flags):
        derived = wally.bip32_key_from_parent_path(
            self.extkey, path, flags | wally.BIP32_FLAG_SKIP_HASH)
        return Bip32Key(derived)

    def derive_prv(self, path):
        """Derive private child key"""
        return self._derive(path, wally.BIP32_FLAG_KEY_PRIVATE)

    def derive_pub(self, path):
        """Derive public child key"""
        return self._derive(path, wally.BIP32_FLAG_KEY_PUBLIC)

    def sign_compact(self, h):
        """Produce a compact signature for (hashed) message h"""
        return self.prvkey.sign_compact(h)

    def sign(self, h):
        """Produce a DER signature for (hashed) message h"""
        return self.prvkey.sign(h)
