from garecovery.key import Bip32Key
from garecovery.output import Green2of2CSVOutput, Green2of2CSVElementsOutput
from garecovery.ga_xpub import derive_ga_xpub
from gaservices.utils.gacommon import get_subaccount_path, is_liquid


class GreenSubaccount(object):
    """A Green subaccount"""

    def __init__(self, xprv, service_xpub, subaccount_pointer, network='mainnet'):
        self.xprv = xprv   # Bip32Key
        self.service_xpub = service_xpub  # Bip32Key
        self.subaccount_pointer = subaccount_pointer
        self.network = network

    @classmethod
    def from_master_xprv(cls, master_xprv, gait_path, subaccount_pointer, network='mainnet'):
        """Create Green subaccount from the wallet master private key"""
        # FIXME: handle branch somewhere else
        user_path = get_subaccount_path(subaccount_pointer) + [1]
        xprv = Bip32Key.from_b58(master_xprv).derive_prv(user_path)
        service_xpub = Bip32Key(derive_ga_xpub(gait_path, subaccount_pointer or None, network))
        return cls(xprv, service_xpub, subaccount_pointer, network)


class Green2of2Subaccount(GreenSubaccount):
    """A Green 2of2 subaccount"""

    def get_csv_output(self, pointer, csv_blocks):
        """Produce a CSV output"""
        key = self.xprv.derive_prv([pointer])
        service_pubkey = self.service_xpub.derive_pub([pointer]).pub
        if is_liquid(self.network):
            return Green2of2CSVElementsOutput(key, service_pubkey, csv_blocks, self.network)
        return Green2of2CSVOutput(key, service_pubkey, csv_blocks, self.network)
