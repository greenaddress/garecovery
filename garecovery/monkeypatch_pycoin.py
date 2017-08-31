import io
import pycoin.tx
from pycoin.encoding import double_sha256
from pycoin.serialize.bitcoin_streamer import stream_struct


# Fix tx hash/id for segwit txs
# This is a backport of the fix already made in the pycoin github repo
# https://github.com/richardkiss/pycoin/commit/a2e4af5180f4676950f4a8b5336b894082120720
def _tx_hash(self, hash_type=None):
    """Return the hash for this Tx object."""
    s = io.BytesIO()
    self.stream(s, include_witness_data=False)
    if hash_type is not None:
        stream_struct("L", s, hash_type)
    return double_sha256(s.getvalue())
pycoin.tx.Tx.hash = _tx_hash
