class GARecoveryError(Exception):
    pass


class BitcoinCoreConnectionError(GARecoveryError):
    pass


class ImportMultiError(GARecoveryError):
    pass


class InvalidDestinationAddressError(GARecoveryError):
    pass


class InvalidMnemonicOrPasswordError(GARecoveryError):
    pass


class NeedMnemonicOrGaXPub(GARecoveryError):
    pass


class NoFeeRate(GARecoveryError):
    pass


class OfileExistsError(GARecoveryError):
    pass
