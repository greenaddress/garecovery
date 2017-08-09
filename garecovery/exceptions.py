class GARecoveryError(Exception):
    pass


class BitcoinCoreConnectionError(GARecoveryError):
    pass


class ImportMultiError(GARecoveryError):
    pass


class NoDestinationAddressError(GARecoveryError):
    pass


class NeedMnemonicOrGaXPub(GARecoveryError):
    pass


class OfileExistsError(GARecoveryError):
    pass


class NoFeeRate(GARecoveryError):
    pass
