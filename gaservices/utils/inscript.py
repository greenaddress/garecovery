""" Utilities for generating input scripts, aka scriptSig/unlocking scripts """
from gaservices.utils.btc_ import gen_pushdata
from wallycore import hex_to_bytes, sha256


def _b(h):
    return hex_to_bytes(h)


def _push(d):
    return bytearray(gen_pushdata(d))


def p2pkh(pubkey_bin, signature_bin):
    return _push(signature_bin) + _push(pubkey_bin)


def witness(script_bin):
    # PUSH(OP_0 PUSH(sha256(script_bin)))
    return _b('220020') + sha256(script_bin)


def multisig(script, signatures):
    multisig = bytearray(_b('00'))
    for signature in signatures:
        multisig += _push(signature)
    return multisig + _push(script)
