""" Transaction utility functions """
import wallycore as wally

# FIXME: remove unused

if type(b'') is str:
    # Python2
    def from_hex(tx_hex):
        return wally.tx_from_hex(tx_hex.encode('ascii'), wally.WALLY_TX_FLAG_USE_WITNESS)
else:
    # Python3
    def from_hex(tx_hex):
        return wally.tx_from_hex(tx_hex, wally.WALLY_TX_FLAG_USE_WITNESS)


def to_hex(tx, use_witness=True):
    return wally.tx_to_hex(tx, wally.WALLY_TX_FLAG_USE_WITNESS if use_witness else 0)


def get_txhash_bin(tx):
    return bytes(wally.sha256d(wally.tx_to_bytes(tx, 0)))


def get_txhash_hex(tx):
    return wally.hex_from_bytes(get_txhash_bin(tx)[::-1])


def new(nlocktime=0, inputs=8, outputs=8, version=wally.WALLY_TX_VERSION_2):
    # Create with room for 8 inputs/outputs by default to reduce re-allocations
    return wally.tx_init(version, nlocktime, inputs, outputs)


def add_input(tx, txhash_bin, i, sequence=0xFFFFFFFF, script=None, witness=None):
    wally.tx_add_raw_input(tx, txhash_bin, i, sequence, script, witness, 0)


def add_output(tx, satoshi, script):
    wally.tx_add_raw_output(tx, int(satoshi), script, 0)


def set_witness(tx, i, witness):
    wally.tx_set_input_witness(tx, i, wally.tx_witness_stack_create(witness))


def get_output_address(tx, i, versions):
    script = wally.tx_get_output_script(tx, i)
    script_type = wally.scriptpubkey_get_type(script)
    if script_type == wally.WALLY_SCRIPT_TYPE_P2PKH:
        return wally.base58check_from_bytes(bytearray([versions[0]]) + script[3:23])
    if script_type == wally.WALLY_SCRIPT_TYPE_P2SH:
        return wally.base58check_from_bytes(bytearray([versions[1]]) + script[2:22])
    assert False


def total_output_satoshi(tx):
    num_outputs = wally.tx_get_num_outputs(tx)
    return sum(wally.tx_get_output_satoshi(tx, i) for i in range(num_outputs))
