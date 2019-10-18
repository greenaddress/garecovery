class GARecoveryError(Exception):
    pass


class BitcoinCoreConnectionError(GARecoveryError):
    pass


class ImportMultiError(GARecoveryError):
    pass


class InsufficientFee(GARecoveryError):
    pass


class InvalidDestinationAddressError(GARecoveryError):
    pass


class InvalidMnemonicOrPasswordError(GARecoveryError):
    pass


class InvalidNetwork(GARecoveryError):
    pass


class InvalidPrivateKey(GARecoveryError):
    pass


class InvalidPublicKey(GARecoveryError):
    pass


class MempoolRejectionError(GARecoveryError):
    pass


class NeedMnemonicOrGaXPub(GARecoveryError):
    pass


class NoFeeRate(GARecoveryError):
    pass


class OfileExistsError(GARecoveryError):
    pass
