import wallycore as wally
from gaservices.utils.gaconstants import get_address_versions, CA_PREFIX


class GreenOutput(object):
    """Base class for Green outputs"""

    def __init__(self, key, service_pubkey, network='mainnet'):
        self.key = key  # ECKey
        self.service_pubkey = service_pubkey  # bytes
        self.network = network


class Green2of2CSVOutput(GreenOutput):
    """P2SH-P2WSH-2of2-CSV Green output"""

    def __init__(self, key, service_pubkey, csv_blocks, network='mainnet'):
        super(Green2of2CSVOutput, self).__init__(key, service_pubkey, network)
        self.csv_blocks = csv_blocks

    def scriptpubkey_csv_2of2_then_1_fn(self, keys, csv_blocks, flags=0):
        return wally.scriptpubkey_csv_2of2_then_1_from_bytes_opt(keys, csv_blocks, flags)

    @property
    def witness_script(self):
        keys = self.service_pubkey + self.key.pub
        return self.scriptpubkey_csv_2of2_then_1_fn(keys, self.csv_blocks)

    @property
    def witness_program(self):
        return wally.sha256(self.witness_script)

    @property
    def redeem_script(self):
        return wally.witness_program_from_bytes(self.witness_script, wally.WALLY_SCRIPT_SHA256)

    @property
    def script_pubkey(self):
        return wally.scriptpubkey_p2sh_from_bytes(self.redeem_script, wally.WALLY_SCRIPT_HASH160)

    @property
    def address(self):
        script_hash = wally.hash160(self.redeem_script)
        # FIXME: be more explicit
        version = bytearray([get_address_versions(self.network)[1]])
        return wally.base58check_from_bytes(version + script_hash)

    def sign(self, h):
        """Produce a DER encoded signature using the user key"""
        return self.key.sign(h)

    @property
    def script_sig(self):
        return wally.script_push_from_bytes(self.redeem_script, 0)

    def get_signed_witness_stack(self, h, sighash):
        return [
            None,
            self.sign(h) + bytes([sighash]),
            self.witness_script]

    def get_signed_witness(self, h, sighash=wally.WALLY_SIGHASH_ALL):
        """Produce witness stack assuming CSV time is expired"""
        return wally.tx_witness_stack_create(self.get_signed_witness_stack(h, sighash))


class Green2of2CSVElementsOutput(Green2of2CSVOutput):
    """P2SH-P2WSH-2of2-CSV Green Elements output"""

    # FIXME: consider adding a seed/master_blinding_key param
    def __init__(self, key, service_pubkey, csv_blocks, network='liquid'):
        super(Green2of2CSVElementsOutput, self).__init__(key, service_pubkey, csv_blocks, network)

    def scriptpubkey_csv_2of2_then_1_fn(self, keys, csv_blocks, flags=0):
        return wally.scriptpubkey_csv_2of2_then_1_from_bytes(keys, csv_blocks, flags)

    def get_signed_witness_stack(self, h, sighash):
        return [
            self.sign(h) + bytes([sighash]),
            self.witness_script]

    def get_private_blinding_key(self, seed):
        master_blinding_key = wally.asset_blinding_key_from_seed(seed)
        return wally.asset_blinding_key_to_ec_private_key(master_blinding_key, self.script_pubkey)

    def get_public_blinding_key(self, seed):
        return wally.ec_public_key_from_private_key(self.get_private_blinding_key(seed))

    def get_confidential_address(self, seed):
        ca_prefix = CA_PREFIX[self.network]
        return wally.confidential_addr_from_addr(
            self.address, ca_prefix, self.get_public_blinding_key(seed))
