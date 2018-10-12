from zipfile import ZipFile
from io import BytesIO

import base64

from . import gaconstants, txutil
import wallycore as wally


def _fernet_decrypt(key, data):
    assert wally.hmac_sha256(key[:16], data[:-32]) == data[-32:]
    res = bytearray(len(data[25:-32]))
    written = wally.aes_cbc(key[16:], data[9:25], data[25:-32], wally.AES_FLAG_DECRYPT, res)
    assert written <= len(res) and len(res) - written <= wally.AES_BLOCK_LEN
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
    priv_key = wally.bip32_key_get_priv_key(key)
    return wally.base58check_from_bytes(ver + priv_key + compressed)


class PassiveSignatory:
    """Represent a signatory for which the keys are not known, only the signature

    For use where a transaction has been partially signed. Instances of this class represent the
    known signatures
    """

    def __init__(self, signature):
        self.signature = wally.ec_sig_from_der(signature[:-1])

    def get_signature(self, preimage_hash):
        return self.signature


class ActiveSignatory:
    """Active signatory for which the keys are known, capable of signing arbitrary data"""

    def __init__(self, key):
        self.key = key

    def get_signature(self, preimage_hash):
        flags = wally.EC_FLAG_ECDSA | wally.EC_FLAG_GRIND_R
        return wally.ec_sig_from_bytes(self.key, preimage_hash, flags)


def _to_der(sig):
    return wally.ec_sig_to_der(sig) + bytearray([wally.WALLY_SIGHASH_ALL])


def sign(txdata, signatories):
    tx = txutil.from_hex(txdata['tx'])
    for i in range(wally.tx_get_num_inputs(tx)):
        script = wally.hex_to_bytes(txdata['prevout_scripts'][i])
        script_type = txdata['prevout_script_types'][i]
        flags, value, sighash = 0, 0, wally.WALLY_SIGHASH_ALL

        if script_type == gaconstants.P2SH_P2WSH_FORTIFIED_OUT:
            flags = wally.WALLY_TX_FLAG_USE_WITNESS
            value = int(txdata['prevout_values'][i])
        preimage_hash = wally.tx_get_btc_signature_hash(tx, i, script, value, sighash, flags)

        sigs = [s.get_signature(preimage_hash) for s in signatories]

        if script_type == gaconstants.P2SH_P2WSH_FORTIFIED_OUT:
            txutil.set_witness(tx, i, [None, _to_der(sigs[0]), _to_der(sigs[1]), script])
            flags = wally.WALLY_SCRIPT_SHA256 | wally.WALLY_SCRIPT_AS_PUSH
            script = wally.witness_program_from_bytes(script, flags)
        else:
            sigs = sigs[0] + sigs[1]
            script = wally.scriptsig_multisig_from_bytes(script, sigs, [sighash, sighash], 0)
        wally.tx_set_input_script(tx, i, script)

    return tx


def countersign(txdata, private_key):
    GreenAddress = PassiveSignatory(wally.hex_to_bytes(txdata['prevout_signatures'][0]))
    user = ActiveSignatory(wally.bip32_key_get_priv_key(private_key))
    return sign(txdata, [GreenAddress, user])


def derive_hd_key(root, path, flags=0):
    return wally.bip32_key_from_parent_path(root, path, flags | wally.BIP32_FLAG_SKIP_HASH)


def get_subaccount_path(subaccount):
    if subaccount == 0:
        return []
    return [gaconstants.HARDENED | 3, gaconstants.HARDENED | subaccount]


def derive_user_private_key(txdata, wallet, branch):
    subaccount = txdata['prevout_subaccounts'][0] or 0
    pointer = txdata['prevout_pointers'][0] or 0
    path = get_subaccount_path(subaccount)
    return derive_hd_key(wallet, path + [branch, pointer])
