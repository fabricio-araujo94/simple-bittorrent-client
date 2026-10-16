"""
Centralized utilities for SHA-1 hash calculation and piece validation.
"""

import hashlib


def compute_sha1(data: bytes) -> bytes:
    """
    Compute and return the 20-byte SHA-1 hash for the provided buffer.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"Expected bytes or bytearray, got {type(data).__name__}.")
    return hashlib.sha1(data).digest()


def verify_sha1(data: bytes, expected_hash: bytes) -> bool:
    """
    Verify whether the SHA-1 hash of the data matches the expected 20-byte hash.
    """
    if len(expected_hash) != 20:
        raise ValueError(f"Expected hash must be exactly 20 bytes, got {len(expected_hash)} bytes.")
    return compute_sha1(data) == expected_hash

