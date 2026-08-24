"""
Testes unitários para a camada de parsing e encoding de Bencode.
"""

import unittest
from src.bencode import (
    decode_bencode,
    decode_bencode_with_offsets,
    encode_bencode,
    BencodeDecodeError,
    BencodeEncodeError,
)


class TestBencode(unittest.TestCase):

    # --- Testes de Inteiros ---

    def test_decode_integers_valid(self):
        self.assertEqual(decode_bencode(b"i0e"), 0)
        self.assertEqual(decode_bencode(b"i42e"), 42)
        self.assertEqual(decode_bencode(b"i-100e"), -100)
        self.assertEqual(decode_bencode(b"i1234567890123456789e"), 1234567890123456789)

    def test_decode_integers_invalid(self):
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"i-0e")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"i03e")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"i-03e")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"i42")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"ie")

    # --- Testes de Strings ---

    def test_decode_strings_valid(self):
        self.assertEqual(decode_bencode(b"4:spam"), b"spam")
        self.assertEqual(decode_bencode(b"0:"), b"")
        # Bytes arbitrários (binário bruto de hashes SHA-1)
        binary_data = b"\x00\x1f\xfe\xca\xfe\xba\xbe"
        self.assertEqual(decode_bencode(b"7:" + binary_data), binary_data)

    def test_decode_strings_invalid(self):
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"4:spa")  # buffer menor que o informado
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"-5:spam")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"04:spam")

    # --- Testes de Listas ---

    def test_decode_list_valid(self):
        self.assertEqual(decode_bencode(b"le"), [])
        self.assertEqual(decode_bencode(b"l4:spami42ee"), [b"spam", 42])
        self.assertEqual(decode_bencode(b"l3:foo3:bare"), [b"foo", b"bar"])
        self.assertEqual(decode_bencode(b"ll4:spamee"), [[b"spam"]])

    def test_decode_list_invalid(self):
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"l4:spam")  # sem 'e' final

    # --- Testes de Dicionários ---

    def test_decode_dict_valid(self):
        self.assertEqual(decode_bencode(b"de"), {})
        self.assertEqual(
            decode_bencode(b"d3:bar4:spam3:fooi42ee"),
            {b"bar": b"spam", b"foo": 42},
        )

    def test_decode_dict_invalid(self):
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"d3:foo")  # incompleto
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"di42e3:fooe")  # chave não é string

    # --- Teste de Raw Byte Offsets ---

    def test_decode_with_offsets(self):
        raw = b"d3:bar4:spam3:fooi42ee"
        val, consumed, slices = decode_bencode_with_offsets(raw)
        self.assertEqual(consumed, len(raw))
        self.assertIn(b"bar", slices)
        self.assertIn(b"foo", slices)

        # Verifica slice de 'foo' -> i42e (offset 16 a 21)
        foo_start, foo_end = slices[b"foo"]
        self.assertEqual(raw[foo_start:foo_end], b"i42e")

    # --- Testes de Encoding ---

    def test_encode_bencode(self):
        self.assertEqual(encode_bencode(0), b"i0e")
        self.assertEqual(encode_bencode(-42), b"i-42e")
        self.assertEqual(encode_bencode(b"spam"), b"4:spam")
        self.assertEqual(encode_bencode("hello"), b"5:hello")
        self.assertEqual(encode_bencode([b"spam", 42]), b"l4:spami42ee")

        # Garante ordenação de chaves no dicionário
        d = {b"foo": 42, b"bar": b"spam"}
        self.assertEqual(encode_bencode(d), b"d3:bar4:spam3:fooi42ee")

    def test_encode_invalid_type(self):
        with self.assertRaises(BencodeEncodeError):
            encode_bencode(3.14)

    def test_roundtrip(self):
        original = {
            b"announce": b"http://tracker.example.com/announce",
            b"info": {
                b"length": 1048576,
                b"name": b"test.bin",
                b"piece length": 262144,
                b"pieces": b"12345678901234567890",
            },
        }
        encoded = encode_bencode(original)
        decoded = decode_bencode(encoded)
        self.assertEqual(decoded, original)


if __name__ == "__main__":
    unittest.main()
