from zipfile import ZipFile
from io import BytesIO

import base64

from pycoin.encoding import to_bytes_32
from pycoin.tx.Tx import Tx, SIGHASH_ALL

from gaservices.utils.btc_ import tx_segwit_hash
from gaservices.utils import inscript
from wallycore import *


def _fernet_decrypt(key, data):
    assert hmac_sha256(key[:16], data[:-32]) == data[-32:]
    res = bytearray(len(data[25:-32]))
    written = aes_cbc(key[16:], data[9:25], data[25:-32], AES_FLAG_DECRYPT, res)
    assert written <= len(res) and len(res) - written <= AES_BLOCK_LEN
    return res[:written]


def _unzip(data, key):
    """Unzip a GreenAddress nlocktimes.zip attachment file.

    The file format is double zip encoded with the user's chaincode
    """
    all_data = []
    if not data.startswith(b'PK'):
        all_data.append(data)
    else:
        # Compressed zip file: unzip it
        zf = ZipFile(BytesIO(data))
        for f in zf.namelist():
            data = b''.join(zf.open(f).readlines())
            prefix = b'GAencrypted'
            if data.startswith(prefix):
                # Encrypted inner zip file: Strip prefix, decrypt and unzip again
                encrypted = data[len(prefix):]
                all_data.extend(_unzip(_fernet_decrypt(key, encrypted), key))
            else:
                all_data.append(data)

    return all_data


def private_key_to_wif(key, testnet):
    ver = b'\xef' if testnet else b'\x80'
    compressed = b'\x01'
    return base58check_from_bytes(ver + bip32_key_get_priv_key(key) + compressed,)


P2SH_P2WSH_FORTIFIED_OUT = SEGWIT = 14


class PassiveSignatory:
    """Represent a signatory for which the keys are not known, only the signature

    For use where a transaction has been partially signed. Instances of this class represent the
    known signatures
    """

    def __init__(self, signature):
        self.signature = signature

    def get_signature(self, sighash):
        return self.signature


class ActiveSignatory:
    """Active signatory for which the keys are known, capable of signing arbitrary data"""

    def __init__(self, key):
        self.key = key

    def get_signature(self, sighash):
        sig = ec_sig_from_bytes(self.key, sighash, EC_FLAG_ECDSA)
        signature = ec_sig_to_der(sig) + bytearray([SIGHASH_ALL, ])
        return signature


def sign(txdata, signatories):
    tx = Tx.from_hex(txdata['tx'])
    for prevout_index, txin in enumerate(tx.txs_in):

        script = hex_to_bytes(txdata['prevout_scripts'][prevout_index])
        script_type = txdata['prevout_script_types'][prevout_index]

        if script_type == SEGWIT:
            value = int(txdata['prevout_values'][prevout_index])
            sighash = tx_segwit_hash(tx, prevout_index, script, value)
        else:
            sighash = to_bytes_32(tx.signature_hash(script, prevout_index, SIGHASH_ALL))

        signatures = [signatory.get_signature(sighash) for signatory in signatories]

        if script_type == SEGWIT:
            tx.set_witness(prevout_index, [b'', ] + signatures + [script, ])
            txin.script = inscript.witness(script)
        else:
            txin.script = inscript.multisig(script, signatures)

    return tx


def countersign(txdata, private_key):
    GreenAddress = PassiveSignatory(hex_to_bytes(txdata['prevout_signatures'][0]))
    user = ActiveSignatory(bip32_key_get_priv_key(private_key))
    return sign(txdata, [GreenAddress, user])


def derive_hd_key(root, path, flags=0):
    return bip32_key_from_parent_path(root, path, flags | BIP32_FLAG_SKIP_HASH)


def get_subaccount_path(subaccount):
    if subaccount == 0:
        return []
    else:
        HARDENED = 0x80000000
        return [HARDENED | 3, HARDENED | subaccount]


def derive_user_private_key(txdata, wallet, branch):
    subaccount = txdata['prevout_subaccounts'][0] or 0
    pointer = txdata['prevout_pointers'][0] or 0
    path = get_subaccount_path(subaccount)
    return derive_hd_key(wallet, path + [branch, pointer])
