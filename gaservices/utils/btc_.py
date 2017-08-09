import struct

from wallycore import sha256d


def bc_int(v):
    if v < 253:
        return struct.pack("<B", v)
    elif v <= 65535:
        return b'\xfd' + struct.pack("<H", v)
    elif v <= 0xffffffff:
        return b'\xfe' + struct.pack("<L", v)
    else:
        return b'\xff' + struct.pack("<Q", v)


def gen_pushdata(data):
    if len(data) == 0:
        return b'\0'
    elif len(data) <= 75:
        return bytearray([len(data),]) + data
    elif len(data) <= 255:
        return bytearray([76, len(data)]) + data
    else:
        return bytearray([77, ]) + struct.pack("<H", len(data)) + data

def tx_segwit_hash(tx, i, script, value):
    # BIP143:

    # 1. nVersion
    tx_bin = struct.pack("<L", 1)

    # 2. hashPrevouts
    to_hash = b""
    for inp in tx.txs_in:
        to_hash += inp.previous_hash
        to_hash += struct.pack("<L", inp.previous_index)
    tx_bin += sha256d(to_hash)

    # 3. hashSequence
    to_hash = b"".join(struct.pack("<L", inp.sequence) for inp in tx.txs_in)
    tx_bin += sha256d(to_hash)

    # 4. transaction id and output index of the output spent by this input
    tx_bin += tx.txs_in[i].previous_hash
    tx_bin += struct.pack("<L", tx.txs_in[i].previous_index)

    # 5. subscript of the input
    tx_bin += bc_int(len(script)) + script

    # 6. value of the output spent by this input
    tx_bin += struct.pack("<Q", value)

    # 7. nSequence of the input
    tx_bin += struct.pack("<L", tx.txs_in[i].sequence)

    # 8. hashOutputs
    to_hash = b""
    for out in tx.txs_out:
        to_hash += struct.pack('<Q', out.coin_value)
        to_hash += bc_int(len(out.script)) + out.script
    tx_bin += sha256d(to_hash)

    # 9. nLockTime
    tx_bin += struct.pack("<L", tx.lock_time)

    # 10. hashType
    tx_bin += struct.pack("<L", 1)

    return sha256d(tx_bin)



