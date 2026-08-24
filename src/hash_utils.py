"""
Utilitários centralizados para cálculo de hashes SHA-1 e validação de peças.
"""

import hashlib


def compute_sha1(data: bytes) -> bytes:
    """
    Calcula e retorna o hash SHA-1 de 20 bytes para o buffer fornecido.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"Esperado bytes ou bytearray, obtido {type(data).__name__}.")
    return hashlib.sha1(data).digest()


def verify_sha1(data: bytes, expected_hash: bytes) -> bool:
    """
    Verifica se o hash SHA-1 dos dados coincide com o hash esperado de 20 bytes.
    """
    if len(expected_hash) != 20:
        raise ValueError(f"Hash esperado deve ter exatamente 20 bytes, obtido {len(expected_hash)} bytes.")
    return compute_sha1(data) == expected_hash
