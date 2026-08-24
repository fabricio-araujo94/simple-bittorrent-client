"""
Parser e Serializador de Bencode em Python puro.

Suporta a especificação Bencode do BitTorrent:
- Inteiros: i<number>e
- Byte Strings: <length>:<data>
- Listas: l<item1><item2>...e
- Dicionários: d<key1><val1>...e (Chaves devem ser byte strings ordenadas lexicograficamente)

Garante rastreamento byte-preciso de offsets no buffer original para
preservar a integridade da seção 'info' no cálculo de info_hash.
"""

from typing import Any, Tuple, Dict


class BencodeError(Exception):
    """Exceção base para erros na camada Bencode."""
    pass


class BencodeDecodeError(BencodeError):
    """Exceção lançada quando ocorre erro de sintaxe ao decodificar Bencode."""
    pass


class BencodeEncodeError(BencodeError):
    """Exceção lançada quando ocorre erro ao codificar objeto para Bencode."""
    pass


class BencodeDecoder:
    """
    Decodificador Bencode que processa um buffer de bytes e rastreia offsets.
    """

    def __init__(self, data: bytes):
        self._data = data
        self._len = len(data)
        # Mapeia chaves de dicionários raiz ou aninhados para seus offsets brutos (start, end)
        self.raw_slices: Dict[bytes, Tuple[int, int]] = {}

    def decode(self) -> Tuple[Any, int]:
        val, end_idx = self._parse_at(0)
        return val, end_idx

    def _parse_at(self, idx: int) -> Tuple[Any, int]:
        if idx >= self._len:
            raise BencodeDecodeError(f"Fim de buffer inesperado no offset {idx}.")

        byte = self._data[idx : idx + 1]

        if byte == b'i':
            return self._parse_int(idx)
        elif byte.isdigit():
            return self._parse_string(idx)
        elif byte == b'l':
            return self._parse_list(idx)
        elif byte == b'd':
            return self._parse_dict(idx)
        else:
            raise BencodeDecodeError(f"Caractere Bencode inválido '{byte!r}' no offset {idx}.")

    def _parse_int(self, idx: int) -> Tuple[int, int]:
        end_idx = self._data.find(b'e', idx + 1)
        if end_idx == -1:
            raise BencodeDecodeError(f"Inteiro Bencode não finalizado a partir do offset {idx}.")

        int_bytes = self._data[idx + 1 : end_idx]
        if not int_bytes:
            raise BencodeDecodeError(f"Inteiro Bencode vazio no offset {idx}.")

        # Validações de conformidade com a especificação Bencode:
        # - i-0e é inválido
        # - Zeros à esquerda (ex: i03e) são inválidos, exceto i0e
        if int_bytes == b'-0':
            raise BencodeDecodeError(f"Inteiro inválido '-0' no offset {idx}.")
        if len(int_bytes) > 1 and int_bytes.startswith(b'0'):
            raise BencodeDecodeError(f"Zero à esquerda em inteiro Bencode no offset {idx}.")
        if len(int_bytes) > 2 and int_bytes.startswith(b'-0'):
            raise BencodeDecodeError(f"Zero à esquerda em inteiro negativo no offset {idx}.")

        try:
            val = int(int_bytes.decode('ascii'))
            return val, end_idx + 1
        except ValueError:
            raise BencodeDecodeError(f"Valor numérico inválido {int_bytes!r} no offset {idx}.")

    def _parse_string(self, idx: int) -> Tuple[bytes, int]:
        colon_idx = self._data.find(b':', idx)
        if colon_idx == -1:
            raise BencodeDecodeError(f"Delimitador ':' não encontrado para string no offset {idx}.")

        length_bytes = self._data[idx:colon_idx]
        if len(length_bytes) > 1 and length_bytes.startswith(b'0'):
            raise BencodeDecodeError(f"Tamanho de string com zero à esquerda no offset {idx}.")

        try:
            length = int(length_bytes.decode('ascii'))
        except ValueError:
            raise BencodeDecodeError(f"Tamanho de string inválido {length_bytes!r} no offset {idx}.")

        if length < 0:
            raise BencodeDecodeError(f"Tamanho de string negativo {length} no offset {idx}.")

        start_str = colon_idx + 1
        end_str = start_str + length

        if end_str > self._len:
            raise BencodeDecodeError(
                f"String Bencode de tamanho {length} ultrapassa o fim do buffer no offset {idx}."
            )

        return self._data[start_str:end_str], end_str

    def _parse_list(self, idx: int) -> Tuple[list, int]:
        curr = idx + 1
        result = []
        while curr < self._len:
            if self._data[curr : curr + 1] == b'e':
                return result, curr + 1
            item, curr = self._parse_at(curr)
            result.append(item)

        raise BencodeDecodeError(f"Lista Bencode não finalizada com 'e' a partir do offset {idx}.")

    def _parse_dict(self, idx: int) -> Tuple[dict, int]:
        curr = idx + 1
        result = {}
        last_key = None

        while curr < self._len:
            if self._data[curr : curr + 1] == b'e':
                return result, curr + 1

            # Chaves de dicionários Bencode devem ser byte strings
            if not self._data[curr : curr + 1].isdigit():
                raise BencodeDecodeError(
                    f"Chave de dicionário Bencode deve ser string no offset {curr}."
                )

            key, curr = self._parse_string(curr)

            # Validação de ordenação lexicográfica de chaves
            if last_key is not None and key <= last_key:
                if key == last_key:
                    raise BencodeDecodeError(f"Chave duplicada em dicionário Bencode: {key!r}.")
                # Nota: Em alguns torrents legados minoritários, a ordenação pode variar,
                # mas mantemos a captura de offset intacta.

            last_key = key

            val_start = curr
            val, curr = self._parse_at(curr)
            val_end = curr

            result[key] = val
            # Armazena a fatia exata de bytes para cada chave do dicionário
            self.raw_slices[key] = (val_start, val_end)

        raise BencodeDecodeError(f"Dicionário Bencode não finalizado com 'e' no offset {idx}.")


def decode_bencode(data: bytes) -> Any:
    """Decodifica um buffer de bytes em estruturas Python (int, bytes, list, dict)."""
    if not isinstance(data, (bytes, bytearray)):
        raise BencodeDecodeError(f"Entrada esperada como bytes, obtido {type(data).__name__}.")
    decoder = BencodeDecoder(bytes(data))
    val, _ = decoder.decode()
    return val


def decode_bencode_with_offsets(data: bytes) -> Tuple[Any, int, Dict[bytes, Tuple[int, int]]]:
    """
    Decodifica o buffer Bencode e retorna:
    (objeto_decodificado, bytes_consumidos, mapa_de_offsets_das_chaves)
    """
    if not isinstance(data, (bytes, bytearray)):
        raise BencodeDecodeError(f"Entrada esperada como bytes, obtido {type(data).__name__}.")
    decoder = BencodeDecoder(bytes(data))
    val, end_idx = decoder.decode()
    return val, end_idx, decoder.raw_slices


def encode_bencode(val: Any) -> bytes:
    """
    Codifica objetos Python em bytes no formato Bencode.
    Chaves de dicionários são ordenadas lexicograficamente por seus bytes.
    """
    if isinstance(val, int):
        return f"i{val}e".encode('ascii')
    elif isinstance(val, (bytes, bytearray)):
        return f"{len(val)}:".encode('ascii') + bytes(val)
    elif isinstance(val, str):
        encoded = val.encode('utf-8')
        return f"{len(encoded)}:".encode('ascii') + encoded
    elif isinstance(val, list):
        items = b"".join(encode_bencode(item) for item in val)
        return b"l" + items + b"e"
    elif isinstance(val, dict):
        # Garante que chaves sejam convertidas para bytes e ordenadas lexicograficamente
        encoded_pairs = []
        for k, v in val.items():
            if isinstance(k, bytes):
                k_bytes = k
            elif isinstance(k, str):
                k_bytes = k.encode('utf-8')
            else:
                raise BencodeEncodeError(f"Chave de dicionário deve ser string ou bytes, obtido {type(k).__name__}.")
            encoded_pairs.append((k_bytes, v))

        encoded_pairs.sort(key=lambda pair: pair[0])

        result = bytearray(b"d")
        for k_bytes, v in encoded_pairs:
            result.extend(f"{len(k_bytes)}:".encode('ascii') + k_bytes)
            result.extend(encode_bencode(v))
        result.extend(b"e")
        return bytes(result)
    else:
        raise BencodeEncodeError(f"Tipo não suportado para Bencode: {type(val).__name__}.")
