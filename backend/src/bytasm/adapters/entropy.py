"""Shannon entropy of a byte string, in bits per byte (0.0 to 8.0).

Entropy is a *measurement* of how evenly byte values are spread. High values
are common in compressed or encrypted data, but also in ordinary resources.
Bytasm applies no threshold and draws no conclusion from it (blueprint 3.2).
"""

import math
from collections import Counter

METHOD = "shannon-bits-per-byte"
# Rounded so the JSON output is stable and easy to read.
DECIMALS = 6


def shannon_entropy(data: bytes) -> float:
    """Return H = -sum(p * log2(p)) over the byte-value frequencies of `data`."""
    if not data:
        raise ValueError("entropy is undefined for empty data")
    total = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        p = count / total
        entropy -= p * math.log2(p)
    # max() turns -0.0 (all bytes equal) into 0.0.
    return max(0.0, round(entropy, DECIMALS))
