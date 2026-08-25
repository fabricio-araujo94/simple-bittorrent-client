"""
Testes unitários abrangentes para o parser e serializador Bencode (BEP 0003).

Cobre:
- Valores simples (inteiros positivos, negativos, zero, big ints, strings);
- Estruturas aninhadas (listas/dicts multinível);
- Dicionários (ordenação lexicográfica estrita, chaves únicas, chaves byte strings);
- Listas (homogêneas, heterogêneas, aninhadas);
- Valores vazios (strings, listas, dicts vazios, int 0);
- Dados inválidos (sintaxe, formatos proibidos, tipos de entrada errados);
- Dados truncados (detecção explícita via BencodeTruncatedError);
- Caracteres binários (bytes nulos, range 0x00-0xFF, hashes SHA-1 de 20 bytes);
- Estruturas grandes (milhares de itens, megabytes de payload);
- Identificação exata de fatias (offsets da seção 'info' para cálculo de info_hash);
- Encoding e roundtrip de tipos suportados.
"""

import hashlib
import unittest
from typing import Dict, List

from src.bencode import (
    BencodeDecoder,
    BencodeDecodeError,
    BencodeEncodeError,
    BencodeError,
    BencodeTruncatedError,
    decode_bencode,
    decode_bencode_with_offsets,
    encode_bencode,
    extract_info_bytes,
)


class TestBencodeIntegers(unittest.TestCase):
    """Testes para decodificação e validação de inteiros Bencode."""

    def test_valid_integers(self):
        self.assertEqual(decode_bencode(b"i0e"), 0)
        self.assertEqual(decode_bencode(b"i1e"), 1)
        self.assertEqual(decode_bencode(b"i42e"), 42)
        self.assertEqual(decode_bencode(b"i-1e"), -1)
        self.assertEqual(decode_bencode(b"i-42e"), -42)
        self.assertEqual(decode_bencode(b"i1000000e"), 1000000)
        self.assertEqual(decode_bencode(b"i-9876543210e"), -9876543210)

    def test_large_integers(self):
        # Inteiros arbitrariamente grandes (além de 64 bits)
        big_int = 1234567890123456789012345678901234567890
        raw = f"i{big_int}e".encode('ascii')
        self.assertEqual(decode_bencode(raw), big_int)

        neg_big_int = -9876543210987654321098765432109876543210
        raw_neg = f"i{neg_big_int}e".encode('ascii')
        self.assertEqual(decode_bencode(raw_neg), neg_big_int)

    def test_invalid_integers_syntax(self):
        # Sinal '+' proibido
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"i+42e")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"i+0e")

        # Zero negativo '-0' e '-00' proibidos
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"i-0e")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"i-00e")

        # Zeros à esquerda proibidos (exceto '0')
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"i03e")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"i00e")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"i-03e")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"i-007e")

        # Inteiro sem dígitos
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"ie")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"i-e")

        # Caracteres não-numéricos ou pontuação
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"i12a3e")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"i1_000e")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"i 42e")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"i3.14e")


class TestBencodeByteStrings(unittest.TestCase):
    """Testes para decodificação e validação de byte strings Bencode."""

    def test_valid_strings(self):
        self.assertEqual(decode_bencode(b"4:spam"), b"spam")
        self.assertEqual(decode_bencode(b"0:"), b"")
        self.assertEqual(decode_bencode(b"11:hello world"), b"hello world")
        self.assertEqual(decode_bencode(b"5:12345"), b"12345")

    def test_bytes_type_guarantee(self):
        # Garante que o retorno é SEMPRE bytes, nunca str
        res = decode_bencode(b"4:spam")
        self.assertIsInstance(res, bytes)
        self.assertNotIsInstance(res, str)

        empty_res = decode_bencode(b"0:")
        self.assertIsInstance(empty_res, bytes)
        self.assertEqual(empty_res, b"")

    def test_invalid_string_length_syntax(self):
        # Zero à esquerda no tamanho
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"04:spam")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"00:")

        # Sinais no tamanho
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"-4:spam")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"+4:spam")

        # Caracteres inválidos ou ausência de tamanho
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b":spam")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"abc:spam")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"4spam")


class TestBencodeLists(unittest.TestCase):
    """Testes para listas Bencode."""

    def test_valid_lists(self):
        self.assertEqual(decode_bencode(b"le"), [])
        self.assertEqual(decode_bencode(b"li1ei2ei3ee"), [1, 2, 3])
        self.assertEqual(decode_bencode(b"l4:spami42ee"), [b"spam", 42])
        self.assertEqual(decode_bencode(b"l0:0:0:e"), [b"", b"", b""])

    def test_nested_lists(self):
        self.assertEqual(decode_bencode(b"ll4:spamee"), [[b"spam"]])
        self.assertEqual(decode_bencode(b"lli1eei2eli3eee"), [[1], 2, [3]])
        self.assertEqual(decode_bencode(b"llli1eeee"), [[[1]]])
        self.assertEqual(decode_bencode(b"llelelee"), [[], [], []])

    def test_invalid_list_element(self):
        # Elemento com caractere desconhecido dentro da lista
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"li1exi2ee")


class TestBencodeDictionaries(unittest.TestCase):
    """Testes para dicionários Bencode e validação BEP 0003."""

    def test_valid_dictionaries(self):
        self.assertEqual(decode_bencode(b"de"), {})
        self.assertEqual(
            decode_bencode(b"d3:bar4:spam3:fooi42ee"),
            {b"bar": b"spam", b"foo": 42},
        )
        self.assertEqual(
            decode_bencode(b"d1:ai1e1:bi2e1:ci3ee"),
            {b"a": 1, b"b": 2, b"c": 3},
        )

    def test_lexicographical_byte_ordering(self):
        # 'aa' vem antes de 'b' em ordem byte-a-byte
        raw = b"d2:aa1:11:b1:2e"
        self.assertEqual(decode_bencode(raw), {b"aa": b"1", b"b": b"2"})

        # Chaves fora de ordem lexicográfica devem lançar erro
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"d1:b1:22:aa1:1e")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"d3:zeta1:a3:alpha1:be")

    def test_duplicate_keys_forbidden(self):
        # Chaves duplicadas não são permitidas
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"d3:foo1:a3:foo1:be")

    def test_non_string_keys_forbidden(self):
        # Chave inteira
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"di42e4:spame")
        # Chave lista
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"dle4:spame")
        # Chave dicionário
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"dde4:spame")

    def test_missing_value_in_dictionary(self):
        # Dicionário termina após a chave sem fornecer o valor
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"d3:fooe")


class TestBencodeNestedStructures(unittest.TestCase):
    """Testes com estruturas aninhadas e heterogêneas."""

    def test_dict_in_dict(self):
        raw = b"d1:ad1:bi1eee"
        expected = {b"a": {b"b": 1}}
        self.assertEqual(decode_bencode(raw), expected)

    def test_list_in_dict(self):
        raw = b"d4:listli1ei2ei3eee"
        expected = {b"list": [1, 2, 3]}
        self.assertEqual(decode_bencode(raw), expected)

    def test_dict_in_list(self):
        raw = b"ld1:ai1eed1:bi2eee"
        expected = [{b"a": 1}, {b"b": 2}]
        self.assertEqual(decode_bencode(raw), expected)

    def test_complex_multilevel_nesting(self):
        data = {
            b"announce": b"http://tracker.org/announce",
            b"info": {
                b"files": [
                    {b"length": 1000, b"path": [b"docs", b"read.me"]},
                    {b"length": 2000, b"path": [b"src", b"main.py"]},
                ],
                b"name": b"project_files",
                b"piece length": 16384,
                b"pieces": b"12345678901234567890",
            },
            b"nodes": [
                [b"127.0.0.1", 6881],
                [b"192.168.1.1", 6889],
            ],
        }
        encoded = encode_bencode(data)
        decoded = decode_bencode(encoded)
        self.assertEqual(decoded, data)


class TestBencodeEmptyValues(unittest.TestCase):
    """Testes para valores vazios e estruturas compostas por vazios."""

    def test_empty_primitives(self):
        self.assertEqual(decode_bencode(b"0:"), b"")
        self.assertEqual(decode_bencode(b"le"), [])
        self.assertEqual(decode_bencode(b"de"), {})
        self.assertEqual(decode_bencode(b"i0e"), 0)

    def test_composite_empty_structures(self):
        raw = b"d0:0:1:a0:1:bde1:clee"
        expected = {
            b"": b"",
            b"a": b"",
            b"b": {},
            b"c": [],
        }
        self.assertEqual(decode_bencode(raw), expected)
        self.assertEqual(encode_bencode(expected), raw)


class TestBencodeTruncatedData(unittest.TestCase):
    """Testes para detecção de dados truncados (BencodeTruncatedError)."""

    def test_empty_buffer(self):
        with self.assertRaises(BencodeTruncatedError):
            decode_bencode(b"")

    def test_truncated_integers(self):
        with self.assertRaises(BencodeTruncatedError):
            decode_bencode(b"i")
        with self.assertRaises(BencodeTruncatedError):
            decode_bencode(b"i-")
        with self.assertRaises(BencodeTruncatedError):
            decode_bencode(b"i42")
        with self.assertRaises(BencodeTruncatedError):
            decode_bencode(b"i-100")

    def test_truncated_strings(self):
        # Truncado antes ou no delimitador ':'
        with self.assertRaises(BencodeTruncatedError):
            decode_bencode(b"4")
        with self.assertRaises(BencodeTruncatedError):
            decode_bencode(b"100")

        # Truncado no payload de bytes
        with self.assertRaises(BencodeTruncatedError):
            decode_bencode(b"4:")
        with self.assertRaises(BencodeTruncatedError):
            decode_bencode(b"4:a")
        with self.assertRaises(BencodeTruncatedError):
            decode_bencode(b"4:abc")
        with self.assertRaises(BencodeTruncatedError):
            decode_bencode(b"1000:small")

    def test_truncated_lists(self):
        with self.assertRaises(BencodeTruncatedError):
            decode_bencode(b"l")
        with self.assertRaises(BencodeTruncatedError):
            decode_bencode(b"li1e")
        with self.assertRaises(BencodeTruncatedError):
            decode_bencode(b"l4:spam")
        with self.assertRaises(BencodeTruncatedError):
            decode_bencode(b"ll4:spame")

    def test_truncated_dictionaries(self):
        with self.assertRaises(BencodeTruncatedError):
            decode_bencode(b"d")
        with self.assertRaises(BencodeTruncatedError):
            decode_bencode(b"d3:bar")
        with self.assertRaises(BencodeTruncatedError):
            decode_bencode(b"d3:bar4:spam")
        with self.assertRaises(BencodeTruncatedError):
            decode_bencode(b"d3:fool4:spame")

    def test_truncated_error_inheritance(self):
        # Garante que BencodeTruncatedError é subclasse de BencodeDecodeError e BencodeError
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"l4:spam")
        with self.assertRaises(BencodeError):
            decode_bencode(b"i42")


class TestBencodeInvalidAndTrailingData(unittest.TestCase):
    """Testes para validação de entradas inválidas e dados extras após o buffer."""

    def test_invalid_input_types(self):
        with self.assertRaises(BencodeDecodeError):
            decode_bencode("i42e")  # type: ignore (str ao invés de bytes)
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(12345)  # type: ignore
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(None)  # type: ignore

    def test_stray_closing_tag(self):
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"e")

    def test_unrecognized_first_byte(self):
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"x")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"?")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"\xff")

    def test_trailing_data_in_strict_mode(self):
        # Por padrão (strict=True), dados extras após o objeto causam erro
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"i42eextra")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"4:spamgarbage")
        with self.assertRaises(BencodeDecodeError):
            decode_bencode(b"le\x00")

    def test_trailing_data_in_non_strict_mode(self):
        # Com strict=False, decodifica o primeiro objeto
        val = decode_bencode(b"i42eextra", strict=False)
        self.assertEqual(val, 42)


class TestBencodeBinaryData(unittest.TestCase):
    """Testes para manipulação e integridade de dados binários arbitrários."""

    def test_null_bytes_in_string(self):
        data = b"foo\x00bar\x00\x00baz\x00"
        raw = f"{len(data)}:".encode('ascii') + data
        decoded = decode_bencode(raw)
        self.assertEqual(decoded, data)

    def test_all_byte_values_0_to_255(self):
        all_bytes = bytes(range(256))
        raw = f"{len(all_bytes)}:".encode('ascii') + all_bytes
        decoded = decode_bencode(raw)
        self.assertEqual(decoded, all_bytes)
        self.assertEqual(encode_bencode(all_bytes), raw)

    def test_sha1_hashes(self):
        # 10 hashes SHA-1 simulados (200 bytes no total)
        hashes = [hashlib.sha1(f"piece_{i}".encode()).digest() for i in range(10)]
        pieces_raw = b"".join(hashes)
        self.assertEqual(len(pieces_raw), 200)

        d = {b"pieces": pieces_raw}
        encoded = encode_bencode(d)
        decoded = decode_bencode(encoded)
        self.assertEqual(decoded[b"pieces"], pieces_raw)

    def test_binary_keys_in_dict(self):
        # Chaves contendo bytes não-ASCII ordenadas lexicograficamente por valor de byte
        k1 = b"\x01\x02"
        k2 = b"\x80\xff"
        k3 = b"\xff\x00"
        d = {k1: 1, k2: 2, k3: 3}
        encoded = encode_bencode(d)
        decoded = decode_bencode(encoded)
        self.assertEqual(decoded, d)


class TestBencodeLargeStructures(unittest.TestCase):
    """Testes de estresse com estruturas grandes e coleções volumosas."""

    def test_large_list_of_integers(self):
        large_list = list(range(10000))
        encoded = encode_bencode(large_list)
        decoded = decode_bencode(encoded)
        self.assertEqual(decoded, large_list)
        self.assertEqual(len(decoded), 10000)

    def test_large_dict_of_items(self):
        large_dict = {f"key_{i:04d}".encode('ascii'): i for i in range(1000)}
        encoded = encode_bencode(large_dict)
        decoded = decode_bencode(encoded)
        self.assertEqual(decoded, large_dict)
        self.assertEqual(len(decoded), 1000)

    def test_large_binary_payload(self):
        # Payload binário de 1 MB
        one_mb_data = b"X" * (1024 * 1024)
        encoded = encode_bencode(one_mb_data)
        decoded = decode_bencode(encoded)
        self.assertEqual(decoded, one_mb_data)
        self.assertEqual(len(decoded), 1024 * 1024)

    def test_deep_nesting(self):
        # 50 níveis de aninhamento de listas
        nested = 42
        for _ in range(50):
            nested = [nested]
        encoded = encode_bencode(nested)
        decoded = decode_bencode(encoded)
        self.assertEqual(decoded, nested)


class TestBencodeInfoSliceTracking(unittest.TestCase):
    """Testes dedicados à extração byte-precisa da seção 'info' para cálculo de info_hash."""

    def setUp(self):
        self.info_dict = {
            b"length": 1048576,
            b"name": b"sample_file.iso",
            b"piece length": 262144,
            b"pieces": hashlib.sha1(b"piece_0").digest() + hashlib.sha1(b"piece_1").digest(),
        }
        self.raw_info = encode_bencode(self.info_dict)
        self.expected_hash = hashlib.sha1(self.raw_info).digest()

    def test_extract_info_slice_from_simple_torrent(self):
        torrent_dict = {
            b"announce": b"http://tracker.example.com/announce",
            b"info": self.info_dict,
        }
        raw_torrent = encode_bencode(torrent_dict)

        decoded, consumed, slices = decode_bencode_with_offsets(raw_torrent)
        self.assertEqual(consumed, len(raw_torrent))
        self.assertIn(b"info", slices)

        start, end = slices[b"info"]
        extracted_info_bytes = raw_torrent[start:end]

        self.assertEqual(extracted_info_bytes, self.raw_info)
        self.assertEqual(hashlib.sha1(extracted_info_bytes).digest(), self.expected_hash)

    def test_extract_info_bytes_helper(self):
        torrent_dict = {
            b"announce": b"http://tracker.example.com/announce",
            b"created by": b"test-client/1.0",
            b"info": self.info_dict,
        }
        raw_torrent = encode_bencode(torrent_dict)
        extracted = extract_info_bytes(raw_torrent)
        self.assertEqual(extracted, self.raw_info)
        self.assertEqual(hashlib.sha1(extracted).digest(), self.expected_hash)

    def test_nested_info_key_collision_isolation(self):
        # Garante que uma chave interna com nome 'info' não sobreponha a fatia da raiz
        torrent_dict = {
            b"announce": b"http://tracker.org",
            b"info": {
                b"extra": {b"info": b"nested_info_string"},
                b"name": b"test.bin",
                b"piece length": 16384,
                b"pieces": b"12345678901234567890",
            },
        }
        raw_torrent = encode_bencode(torrent_dict)
        _, _, slices = decode_bencode_with_offsets(raw_torrent)

        start, end = slices[b"info"]
        extracted = raw_torrent[start:end]

        # O slice extraído DEVE começar com 'd' e ser o dicionário info completo da raiz
        self.assertTrue(extracted.startswith(b"d"))
        self.assertTrue(extracted.endswith(b"e"))
        self.assertEqual(hashlib.sha1(extracted).digest(), hashlib.sha1(encode_bencode(torrent_dict[b"info"])).digest())

    def test_extract_info_missing_raises(self):
        no_info_torrent = encode_bencode({b"announce": b"http://example.com"})
        with self.assertRaises(BencodeDecodeError):
            extract_info_bytes(no_info_torrent)


class TestBencodeEncoding(unittest.TestCase):
    """Testes para o codificador Bencode e roundtrip."""

    def test_encode_primitives(self):
        self.assertEqual(encode_bencode(0), b"i0e")
        self.assertEqual(encode_bencode(-99), b"i-99e")
        self.assertEqual(encode_bencode(b"spam"), b"4:spam")
        self.assertEqual(encode_bencode("spam"), b"4:spam")  # str convertida para utf-8
        self.assertEqual(encode_bencode([]), b"le")
        self.assertEqual(encode_bencode({}), b"de")

    def test_encode_rejects_bool(self):
        # Em Python, bool é subclasse de int (isinstance(True, int) == True).
        # Bencode não suporta bool e deve rejeitar explicitamente.
        with self.assertRaises(BencodeEncodeError):
            encode_bencode(True)
        with self.assertRaises(BencodeEncodeError):
            encode_bencode(False)
        with self.assertRaises(BencodeEncodeError):
            encode_bencode({b"key": True})
        with self.assertRaises(BencodeEncodeError):
            encode_bencode({True: b"val"})

    def test_encode_rejects_unsupported_types(self):
        with self.assertRaises(BencodeEncodeError):
            encode_bencode(3.14159)
        with self.assertRaises(BencodeEncodeError):
            encode_bencode(None)
        with self.assertRaises(BencodeEncodeError):
            encode_bencode({1, 2, 3})
        with self.assertRaises(BencodeEncodeError):
            encode_bencode({123: b"val"})  # chave não é string/bytes

    def test_encode_detects_duplicate_keys(self):
        # Dicionário com chaves colidindo após conversão str -> bytes
        d = {b"key": 1, "key": 2}
        with self.assertRaises(BencodeEncodeError):
            encode_bencode(d)

    def test_encode_tuples_as_lists(self):
        # Tuplas devem ser codificadas como listas Bencode
        self.assertEqual(encode_bencode((1, 2, b"three")), b"li1ei2e5:threee")

    def test_roundtrip_all_types(self):
        original = {
            b"int_pos": 12345,
            b"int_neg": -6789,
            b"int_zero": 0,
            b"string_ascii": b"hello world",
            b"string_binary": b"\x00\xff\xfe\xca\xfe\xba\xbe",
            b"list_empty": [],
            b"list_nested": [1, [2, [3, b"deep"]]],
            b"dict_empty": {},
            b"dict_nested": {
                b"a": 1,
                b"b": [b"x", b"y"],
                b"c": {b"nested_key": b"nested_val"},
            },
        }
        encoded = encode_bencode(original)
        decoded = decode_bencode(encoded)
        self.assertEqual(decoded, original)


if __name__ == "__main__":
    unittest.main()

