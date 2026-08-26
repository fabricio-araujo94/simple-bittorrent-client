"""
Parser e Serializador de Bencode em Python puro.

Suporta a especificação Bencode do BitTorrent (BEP 0003):
- Inteiros: i<number>e
- Byte Strings: <length>:<data>
- Listas: l<item1><item2>...e
- Dicionários: d<key1><val1>...e (Chaves devem ser byte strings ordenadas lexicograficamente)

Garante rastreamento byte-preciso de offsets no buffer original para
preservar a integridade da seção 'info' no cálculo de info_hash.
"""

from typing import Any, Dict, List, Optional, Tuple, Union


class BencodeError(Exception):
    """Exceção base para erros na camada Bencode."""
    pass


class BencodeDecodeError(BencodeError):
    """Exceção lançada quando ocorre erro de sintaxe ou tipo ao decodificar Bencode."""
    pass


class BencodeTruncatedError(BencodeDecodeError):
    """Exceção lançada quando os dados Bencode terminam prematuramente (dados truncados)."""
    pass


class BencodeEncodeError(BencodeError):
    """Exceção lançada quando ocorre erro ao codificar objeto para Bencode."""
    pass


MAX_BENCODE_DEPTH = 100
MAX_INT_DIGITS = 64
MAX_BENCODE_STRING_LENGTH = 100 * 1024 * 1024  # 100 MB


class BencodeDecoder:
    """
    Decodificador Bencode com validação estrita da especificação BEP 0003,
    proteção contra ataques de profundidade/memória (DoS) e rastreamento de offsets.
    """

    def __init__(self, data: bytes, max_depth: int = MAX_BENCODE_DEPTH):
        self._data = data
        self._len = len(data)
        self.max_depth = max_depth
        # Mapeia chaves do dicionário raiz para seus offsets brutos (start, end)
        self.raw_slices: Dict[bytes, Tuple[int, int]] = {}
        # Mapeia caminhos de chaves (tuplas) para offsets brutos (start, end)
        self.raw_slices_by_path: Dict[Tuple[bytes, ...], Tuple[int, int]] = {}

    def decode(self) -> Tuple[Any, int]:
        """
        Decodifica o primeiro valor Bencode a partir do início do buffer.
        Retorna (objeto_decodificado, proximo_indice).
        """
        if self._len == 0:
            raise BencodeTruncatedError("Buffer vazio. Nenhum dado Bencode para decodificar.")
        val, end_idx = self._parse_at(0, depth=0)
        return val, end_idx

    def _parse_at(
        self, idx: int, depth: int = 0, current_path: Tuple[bytes, ...] = ()
    ) -> Tuple[Any, int]:
        if depth > self.max_depth:
            raise BencodeDecodeError(
                f"Profundidade máxima de aninhamento ({self.max_depth}) excedida no Bencode (potencial ataque DoS)."
            )

        if idx >= self._len:
            raise BencodeTruncatedError(f"Fim de buffer inesperado no offset {idx}.")

        byte = self._data[idx : idx + 1]

        if byte == b'i':
            return self._parse_int(idx)
        elif byte.isdigit():
            return self._parse_string(idx)
        elif byte == b'l':
            return self._parse_list(idx, depth=depth)
        elif byte == b'd':
            return self._parse_dict(idx, depth=depth, current_path=current_path)
        elif byte == b'e':
            raise BencodeDecodeError(f"Terminador 'e' inesperado fora de contexto no offset {idx}.")
        else:
            raise BencodeDecodeError(f"Caractere Bencode inválido {byte!r} no offset {idx}.")

    def _parse_int(self, idx: int) -> Tuple[int, int]:
        end_idx = self._data.find(b'e', idx + 1)
        if end_idx == -1:
            raise BencodeTruncatedError(
                f"Inteiro Bencode truncado: terminador 'e' não encontrado a partir do offset {idx}."
            )

        int_bytes = self._data[idx + 1 : end_idx]
        if not int_bytes:
            raise BencodeDecodeError(f"Inteiro Bencode vazio no offset {idx}.")

        if len(int_bytes) > MAX_INT_DIGITS:
            raise BencodeDecodeError(
                f"Tamanho de inteiro Bencode ({len(int_bytes)} dígitos) excede o limite seguro de {MAX_INT_DIGITS} dígitos."
            )

        # Validações estritas de conformidade com BEP 0003:
        # 1. Não pode ter sinal '+'
        # 2. Se começar com '-', não pode ser '-0' nem ter zeros à esquerda
        # 3. Se for positivo, não pode ter zeros à esquerda (exceto '0')
        # 4. Apenas dígitos ASCII são permitidos
        if int_bytes.startswith(b'+'):
            raise BencodeDecodeError(f"Sinal '+' não permitido em inteiro Bencode no offset {idx}.")

        if int_bytes.startswith(b'-'):
            digits = int_bytes[1:]
            if not digits:
                raise BencodeDecodeError(f"Inteiro negativo incompleto 'i-e' no offset {idx}.")
            if digits == b'0' or digits.startswith(b'0'):
                raise BencodeDecodeError(
                    f"Zero à esquerda ou '-0' inválido em inteiro negativo no offset {idx}."
                )
            if not digits.isdigit():
                raise BencodeDecodeError(
                    f"Caracteres não-numéricos em inteiro Bencode {int_bytes!r} no offset {idx}."
                )
        else:
            if len(int_bytes) > 1 and int_bytes.startswith(b'0'):
                raise BencodeDecodeError(
                    f"Zero à esquerda não permitido em inteiro Bencode no offset {idx}."
                )
            if not int_bytes.isdigit():
                raise BencodeDecodeError(
                    f"Caracteres não-numéricos em inteiro Bencode {int_bytes!r} no offset {idx}."
                )

        try:
            val = int(int_bytes.decode('ascii'))
            return val, end_idx + 1
        except ValueError:
            raise BencodeDecodeError(f"Valor numérico inválido {int_bytes!r} no offset {idx}.")

    def _parse_string(self, idx: int) -> Tuple[bytes, int]:
        colon_idx = self._data.find(b':', idx)
        if colon_idx == -1:
            # Se contém apenas dígitos até o fim do buffer, o delimitador ':' foi truncado
            length_part = self._data[idx:]
            if length_part.isdigit():
                raise BencodeTruncatedError(
                    f"String Bencode truncada: delimitador ':' não encontrado a partir do offset {idx}."
                )
            raise BencodeDecodeError(
                f"Delimitador ':' não encontrado para string a partir do offset {idx}."
            )

        length_bytes = self._data[idx:colon_idx]
        if not length_bytes:
            raise BencodeDecodeError(f"Tamanho de string ausente antes de ':' no offset {idx}.")

        if length_bytes.startswith(b'+') or length_bytes.startswith(b'-'):
            raise BencodeDecodeError(
                f"Sinal não permitido no tamanho de string Bencode no offset {idx}."
            )

        if not length_bytes.isdigit():
            raise BencodeDecodeError(
                f"Tamanho de string deve conter apenas dígitos ASCII, obtido {length_bytes!r} no offset {idx}."
            )

        if len(length_bytes) > 1 and length_bytes.startswith(b'0'):
            raise BencodeDecodeError(
                f"Zero à esquerda não permitido no tamanho de string no offset {idx}."
            )

        try:
            length = int(length_bytes.decode('ascii'))
        except ValueError:
            raise BencodeDecodeError(f"Tamanho de string inválido {length_bytes!r} no offset {idx}.")

        if length > MAX_BENCODE_STRING_LENGTH:
            raise BencodeDecodeError(
                f"Tamanho de string Bencode ({length} bytes) excede o limite máximo permitido ({MAX_BENCODE_STRING_LENGTH} bytes)."
            )

        start_str = colon_idx + 1
        end_str = start_str + length

        if end_str > self._len:
            missing = end_str - self._len
            raise BencodeTruncatedError(
                f"String Bencode truncada no offset {idx}: esperava {length} bytes, "
                f"mas restam apenas {self._len - start_str} bytes no buffer (faltam {missing} bytes)."
            )

        return self._data[start_str:end_str], end_str

    def _parse_list(self, idx: int, depth: int = 0) -> Tuple[list, int]:
        curr = idx + 1
        result = []
        while curr < self._len:
            if self._data[curr : curr + 1] == b'e':
                return result, curr + 1
            item, curr = self._parse_at(curr, depth=depth + 1)
            result.append(item)

        raise BencodeTruncatedError(
            f"Lista Bencode truncada: terminador 'e' não encontrado a partir do offset {idx}."
        )

    def _parse_dict(
        self, idx: int, depth: int = 0, current_path: Tuple[bytes, ...] = ()
    ) -> Tuple[dict, int]:
        curr = idx + 1
        result = {}
        last_key: Optional[bytes] = None

        while curr < self._len:
            if self._data[curr : curr + 1] == b'e':
                return result, curr + 1

            # Chaves de dicionários Bencode DEVEM ser byte strings
            first_byte = self._data[curr : curr + 1]
            if not first_byte.isdigit():
                raise BencodeDecodeError(
                    f"Chave de dicionário Bencode deve ser string no offset {curr} (encontrado {first_byte!r})."
                )

            key, curr = self._parse_string(curr)

            # Validação estrita de ordenação lexicográfica de chaves (BEP 0003)
            if last_key is not None:
                if key == last_key:
                    raise BencodeDecodeError(
                        f"Chave duplicada em dicionário Bencode: {key!r} no offset {curr}."
                    )
                if key < last_key:
                    raise BencodeDecodeError(
                        f"Chaves de dicionário fora de ordem lexicográfica: "
                        f"{last_key!r} apareceu antes de {key!r} no offset {curr}."
                    )

            last_key = key

            # Se o buffer terminar imediatamente após a chave, faltou o valor
            if curr >= self._len:
                raise BencodeTruncatedError(
                    f"Dicionário Bencode truncado: valor ausente para a chave {key!r} no offset {curr}."
                )

            val_start = curr
            val_path = current_path + (key,)
            val, curr = self._parse_at(curr, depth=depth + 1, current_path=val_path)
            val_end = curr

            result[key] = val

            # Registra fatias brutas
            # Se for dicionário raiz (depth == 0), salva em raw_slices
            if depth == 0:
                self.raw_slices[key] = (val_start, val_end)

            # Sempre salva no mapa de caminhos completos
            self.raw_slices_by_path[val_path] = (val_start, val_end)

        raise BencodeTruncatedError(
            f"Dicionário Bencode truncado: terminador 'e' não encontrado a partir do offset {idx}."
        )


def decode_bencode(data: Union[bytes, bytearray, memoryview], strict: bool = True) -> Any:
    """
    Decodifica um buffer de bytes em estruturas Python (int, bytes, list, dict).

    Args:
        data: Buffer contendo os dados Bencoded.
        strict: Se True, garante que todos os bytes do buffer foram consumidos.

    Returns:
        O objeto Python decodificado.

    Raises:
        BencodeTruncatedError: Se os dados terminarem prematuramente.
        BencodeDecodeError: Se os dados forem malformados ou inválidos.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise BencodeDecodeError(f"Entrada esperada como bytes, obtido {type(data).__name__}.")

    bytes_data = bytes(data)
    if not bytes_data:
        raise BencodeTruncatedError("Buffer vazio. Nenhum dado Bencode para decodificar.")

    decoder = BencodeDecoder(bytes_data)
    val, end_idx = decoder.decode()

    if strict and end_idx < len(bytes_data):
        trailing_len = len(bytes_data) - end_idx
        raise BencodeDecodeError(
            f"Dados extras ({trailing_len} bytes) encontrados após o fim do objeto Bencode no offset {end_idx}."
        )

    return val


def decode_bencode_with_offsets(
    data: Union[bytes, bytearray, memoryview]
) -> Tuple[Any, int, Dict[bytes, Tuple[int, int]]]:
    """
    Decodifica o buffer Bencode e retorna:
    (objeto_decodificado, bytes_consumidos, mapa_de_offsets_das_chaves_raiz)
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise BencodeDecodeError(f"Entrada esperada como bytes, obtido {type(data).__name__}.")

    bytes_data = bytes(data)
    if not bytes_data:
        raise BencodeTruncatedError("Buffer vazio. Nenhum dado Bencode para decodificar.")

    decoder = BencodeDecoder(bytes_data)
    val, end_idx = decoder.decode()
    return val, end_idx, decoder.raw_slices


def extract_info_bytes(data: Union[bytes, bytearray, memoryview]) -> bytes:
    """
    Extrai os bytes brutos exatos da seção 'info' de um torrent bencoded
    para cálculo direto do info_hash SHA-1.
    """
    bytes_data = bytes(data)
    val, _, slices = decode_bencode_with_offsets(bytes_data)
    if not isinstance(val, dict):
        raise BencodeDecodeError("Raiz Bencode deve ser um dicionário para extração de 'info'.")
    if b"info" not in slices:
        raise BencodeDecodeError("Chave 'info' não encontrada no dicionário raiz.")
    start, end = slices[b"info"]
    return bytes_data[start:end]


def encode_bencode(val: Any) -> bytes:
    """
    Codifica objetos Python em bytes no formato Bencode.

    Tipos suportados:
    - int (não bool) -> i<val>e
    - bytes, bytearray, memoryview -> <len>:<bytes>
    - str -> <len_utf8>:<utf8_bytes>
    - list, tuple -> l<item1><item2>...e
    - dict -> d<key1><val1><key2><val2>...e (chaves ordenadas lexicograficamente)

    Raises:
        BencodeEncodeError: Se o tipo não for suportado ou se houver chaves duplicadas/inválidas.
    """
    if isinstance(val, bool):
        raise BencodeEncodeError("Tipo booleano ('bool') não é suportado pelo formato Bencode.")
    elif isinstance(val, int):
        return f"i{val}e".encode('ascii')
    elif isinstance(val, (bytes, bytearray, memoryview)):
        raw = bytes(val)
        return f"{len(raw)}:".encode('ascii') + raw
    elif isinstance(val, str):
        encoded = val.encode('utf-8')
        return f"{len(encoded)}:".encode('ascii') + encoded
    elif isinstance(val, (list, tuple)):
        items = b"".join(encode_bencode(item) for item in val)
        return b"l" + items + b"e"
    elif isinstance(val, dict):
        encoded_pairs = []
        seen_keys = set()
        for k, v in val.items():
            if isinstance(k, bool):
                raise BencodeEncodeError("Chave booleana não é suportada em Bencode.")
            elif isinstance(k, (bytes, bytearray, memoryview)):
                k_bytes = bytes(k)
            elif isinstance(k, str):
                k_bytes = k.encode('utf-8')
            else:
                raise BencodeEncodeError(
                    f"Chave de dicionário deve ser string ou bytes, obtido {type(k).__name__}."
                )
            if k_bytes in seen_keys:
                raise BencodeEncodeError(
                    f"Chave duplicada detectada ao codificar dicionário: {k_bytes!r}."
                )
            seen_keys.add(k_bytes)
            encoded_pairs.append((k_bytes, v))

        # Ordenação lexicográfica estrita por bytes
        encoded_pairs.sort(key=lambda pair: pair[0])

        result = bytearray(b"d")
        for k_bytes, v in encoded_pairs:
            result.extend(f"{len(k_bytes)}:".encode('ascii') + k_bytes)
            result.extend(encode_bencode(v))
        result.extend(b"e")
        return bytes(result)
    else:
        raise BencodeEncodeError(f"Tipo não suportado para Bencode: {type(val).__name__}.")
