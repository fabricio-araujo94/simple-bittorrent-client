# Cliente BitTorrent Educacional em Python Puro

Um cliente BitTorrent completo, modular e de fins educacionais desenvolvido em Python moderno (sem dependências externas para o protocolo), implementando os padrões oficiais do BitTorrent (BEP 0003, BEP 0012, BEP 0020, BEP 0023).

O projeto foi desenhado com forte separação de responsabilidades, alta testabilidade, tipagem estrita (*type hints*) e foco em clareza arquitetural para quem deseja aprender como o protocolo BitTorrent realmente funciona por baixo dos panos.

---

## Índice

- [Visão Geral e Protocolo BitTorrent](#visão-geral-e-protocolo-bittorrent)
- [Funcionalidades Implementadas](#funcionalidades-implementadas)
- [Estrutura do Projeto e Arquitetura](#estrutura-do-projeto-e-arquitetura)
- [Instalação](#instalação)
- [Como Executar](#como-executar)
- [Opções de Configuração](#opções-de-configuração)
- [Executando a Suíte de Testes](#executando-a-suíte-de-testes)
- [Limitações Conhecidas e Fora de Escopo](#limitações-conhecidas-e-fora-de-escopo)
- [Licença](#licença)

---

## Visão Geral e Protocolo BitTorrent

O BitTorrent é um protocolo de transferência de arquivos *peer-to-peer* (P2P). Em vez de baixar um arquivo de um servidor central, o arquivo é fragmentado em partes menores distribuídas entre múltiplos nós (*peers*) participantes do enxame (*swarm*).

### O Ciclo de Vida de um Download BitTorrent

O processo de download segue as seguintes etapas em sequência:

1. **Leitura e parsing do `.torrent`**: O arquivo `.torrent` é lido como bytes brutos e decodificado pelo parser Bencode nativo. Os metadados extraídos incluem o nome do arquivo, o tamanho das peças e os hashes SHA-1 de cada peça.

2. **Cálculo do `info_hash`**: A seção `info` do arquivo `.torrent` é identificada no buffer original por *byte slicing* (sem re-serialização) e o SHA-1 é aplicado diretamente sobre esses bytes. O resultado de 20 bytes é o identificador único do torrent, usado em todas as comunicações com trackers e peers.

3. **Comunicação com o Tracker HTTP**: O cliente envia uma requisição `HTTP GET` ao tracker anunciando o início do download. A requisição contém o `info_hash`, o `peer_id` gerado, a porta local e as estatísticas de progresso. O tracker responde com uma lista de endereços IP e portas dos peers participantes do enxame, geralmente em formato compacto IPv4 de 6 bytes (BEP 0023).

4. **Handshake TCP com os Peers**: Para cada peer da lista, o cliente abre uma conexão TCP e executa o handshake de 68 bytes: prefixo do protocolo (`BitTorrent protocol`), 8 bytes de extensões (zerados), `info_hash` de 20 bytes e `peer_id` de 20 bytes. O peer responde com sua própria versão do handshake; se o `info_hash` não coincidir, a conexão é encerrada imediatamente.

5. **Negociação de estado via Peer Wire Protocol**: Após o handshake, os peers trocam mensagens de estado. O cliente envia `Interested` (id 2) para sinalizar que deseja baixar dados. O peer responde com `Unchoke` (id 1) quando decide liberar o envio. O peer também informa quais peças possui via `Bitfield` (id 5) ou mensagens `Have` (id 4) individuais. As mensagens `Choke` (id 0) e `Not Interested` (id 3) sinalizam suspensão de envio e desinteresse, respectivamente.

6. **Seleção e requisição de blocos (Rare Piece First)**: O `PieceManager` agrega os bitfields de todos os peers conectados e calcula a frequência de disponibilidade de cada peça no enxame. As peças com menor disponibilidade são priorizadas. Cada peça é subdividida em blocos de 16 KiB e as mensagens `Request` (id 6) são enviadas com *pipelining*, ou seja, múltiplas requisições em voo simultâneas por peer para maximizar o uso da banda.

7. **Recepção, validação e montagem**: Ao receber mensagens `Piece` (id 7), os blocos são armazenados em memória pelo `PieceManager`. Quando todos os blocos de uma peça chegam, o SHA-1 da peça montada é comparado com o hash registrado nos metadados. Se a verificação passar, a peça é marcada como concluída; caso contrário, todos os seus blocos são descartados e re-solicitados.

8. **Gravação final no disco**: Após todas as peças serem validadas com sucesso, os dados são escritos no arquivo de destino e o tracker é notificado com o evento `completed`.

---

## Funcionalidades Implementadas

- **Parser Bencode 100% Nativo**: Decodificador e codificador em Python puro, com validação estrita (BEP 0003), rejeição de inteiros malformados e proteção contra ataques DoS (limites de profundidade e tamanho).
- **Captura Byte-Precisa do `info_hash`**: Extração direta por *byte slicing* do buffer de entrada, garantindo que o SHA-1 nunca seja corrompido por re-serializações.
- **Leitura de Metadados `.torrent`**: Suporte completo a torrents *Single-file* e *Multi-file* (criação automática de árvores de diretórios).
- **Comunicação com Trackers HTTP/HTTPS**: Utiliza `urllib.request` com URL-encoding estrito (`quote_from_bytes`), suporte a múltiplos trackers/tiers (*announce-list* BEP 0012) com *fallback* automático.
- **Decodificação de Peers Compactos**: Suporte a respostas com peers binários IPv4 (6 bytes por peer - BEP 0023) e dicionários tradicionais.
- **Peer Wire Protocol Robusto**:
	- Handshake de 68 bytes;
	- Desfragmentação TCP com leitura exata e buffer para mensagens coalescidas;
	- Mensagens: `Keep-Alive`, `Choke`, `Unchoke`, `Interested`, `Not Interested`, `Have`, `Bitfield`, `Request`, `Piece`, `Cancel`, `Port`.
- **Request Pipelining**: Envio concorrente de múltiplos blocos de 16 KiB em voo (*in-flight*) por peer para alta vazão de rede.
- **Gerenciador de Peças Concorrente (Thread-Safe)**: Montagem de blocos fora de ordem, descarte de duplicatas e proteção por *Locks*.
- **Estratégia Rare Piece First**: Priorização dinâmica das peças menos disponíveis no enxame.
- **Validação Criptográfica SHA-1**: Verificação rigorosa de integridade de 100% das peças antes da escrita.
- **Múltiplos Peers Simultâneos**: Concorrência via *Worker Threads* com isolamento de falhas (desconexões re-enfileiram blocos automaticamente).
- **Retomada de Download (Auto-Resume)**: Validação por SHA-1 de arquivos parciais pré-existentes no disco, baixando apenas as peças faltantes.
- **Segurança e Sanitização**: Proteção contra *Path Traversal* em nomes de arquivos e limites rígidos de memória por socket.
- **CLI Interativa**: Interface de linha de comando com barra de progresso em tempo real, cálculo de velocidade e inspeção de metadados (`--info`).

---

## Estrutura do Projeto e Arquitetura

```
simple-bittorrent-client/
├── main.py                     # Ponto de entrada raiz para execução rápida
├── README.md                   # Documentação completa
├── pyproject.toml              # Metadados do projeto Python
├── src/                        # Código-fonte modular
│   ├── __init__.py             # Exportações públicas do pacote
│   ├── bencode.py              # Parser e Serializador de Bencode puro Python
│   ├── hash_utils.py           # Utilitários centralizados de hashing SHA-1
│   ├── torrent.py              # Metadados .torrent e extração do info_hash
│   ├── tracker.py              # Cliente HTTP Tracker (urllib) e parsing de peers
│   ├── peer.py                 # Protocolo TCP Wire, Handshake, Bitfield e Mensagens
│   ├── piece_manager.py        # Controle de peças/blocos, SHA-1 e Rarest First
│   ├── client.py               # Orquestrador unificado de download multi-peer
│   └── cli.py                  # Interface de Linha de Comando (CLI)
└── tests/                      # Suíte de testes automatizados (200+ testes)
    ├── __init__.py
    ├── simulators.py           # Servidores fake locais de HTTP Tracker e TCP Peers
    ├── test_bencode.py         # Testes unitários do parser Bencode
    ├── test_hash_utils.py      # Testes unitários de SHA-1
    ├── test_torrent.py         # Testes de metadados e integridade de info_hash
    ├── test_tracker.py         # Testes do cliente HTTP Tracker
    ├── test_peer.py            # Testes do Wire Protocol e framing TCP
    ├── test_piece_manager.py   # Testes do montador de blocos e validação
    ├── test_rarest_first.py    # Testes do algoritmo Rare Piece First
    ├── test_client.py          # Testes do cliente integrado
    ├── test_multi_peer.py      # Testes de download concorrente multi-peer
    ├── test_integration.py     # Testes de integração ponta a ponta (E2E)
    ├── test_robustness.py      # Testes de resiliência e recuperação de falhas
    └── test_security.py        # Testes de segurança (Path Traversal, limites DoS)
```

### Relação entre Módulos

O ponto de entrada é o `main.py` (ou `src/cli.py`), que instancia e aciona o `TorrentClient` (`src/client.py`). O `TorrentClient` é o módulo orquestrador e coordena todos os demais.

O `TorrentClient` depende de dois subsistemas principais em paralelo:

- **`HTTPTrackerClient` (`src/tracker.py`)**: É acionado pelo `TorrentClient` para obter a lista de peers junto ao tracker HTTP. Internamente usa `bencode.py` para decodificar a resposta do tracker e `hash_utils.py` para construir a URL de anúncio.

- **`PieceManager` (`src/piece_manager.py`)**: Mantém o estado de todas as peças e blocos do download. É consultado pelo `TorrentClient` para saber qual bloco solicitar a seguir (algoritmo Rare Piece First) e é alimentado com os blocos recebidos dos peers. Usa `hash_utils.py` para validar cada peça via SHA-1.

Para cada peer da lista, o `TorrentClient` cria uma instância de `PeerConnection` (`src/peer.py`), que encapsula o socket TCP, o handshake e a troca de mensagens Wire Protocol. O `TorrentClient` coordena o `PeerConnection` e o `PieceManager` juntos: obtém o próximo bloco a baixar via `PieceManager`, envia o `Request` pelo `PeerConnection`, e entrega o bloco recebido de volta ao `PieceManager`.

Os módulos de baixo nível `bencode.py` e `hash_utils.py` são usados por vários módulos, mas não dependem de nenhum outro módulo interno do projeto.

---

## Instalação

### Pré-requisitos

- Python 3.8+ (recomendado Python 3.10 ou superior).

### Clonando o Repositório

```bash
git clone https://github.com/fabricio-araujo94/simple-bittorrent-client.git
cd simple-bittorrent-client
```

---

## Como Executar

Você pode executar o cliente diretamente através do `main.py` ou como módulo `src.cli`:

### A. Inspecionar Metadados do Torrent (sem iniciar download)

```bash
python main.py caminho/para/arquivo.torrent --info
```

### B. Baixar um Arquivo Torrent

```bash
# Download básico salvando no diretório atual
python main.py caminho/para/arquivo.torrent

# Download especificando diretório de destino e número de workers
python main.py caminho/para/arquivo.torrent -o ./downloads -w 8 -f 6

# Download com retomada de arquivos parciais já existentes (resume)
python main.py caminho/para/arquivo.torrent -o ./downloads --auto-resume

# Download com logs detalhados de depuração
python main.py caminho/para/arquivo.torrent -v
```

---

## Opções de Configuração

Ao utilizar a interface de linha de comando (`main.py` / `src.cli`), os seguintes parâmetros estão disponíveis:

| Parâmetro               | Padrão                | Descrição                                                                                       |
| :---------------------- | :-------------------- | :---------------------------------------------------------------------------------------------- |
| `torrent`               | (Obrigatório)         | Caminho para o arquivo `.torrent`.                                                              |
| `-o`, `--output`        | `.` (Diretório atual) | Diretório ou arquivo de destino onde os dados baixados serão gravados.                          |
| `-w`, `--workers`       | `4`                   | Número de threads concorrentes para conexão simultânea a múltiplos peers.                       |
| `-f`, `--max-in-flight` | `4`                   | Quantidade máxima de mensagens `Request` de 16 KB enviadas em paralelo por peer (*pipelining*). |
| `-t`, `--timeout`       | `10.0`                | Timeout de socket em segundos para operações de rede com os peers.                              |
| `--tracker-timeout`     | `15.0`                | Timeout em segundos para requisições HTTP ao tracker.                                           |
| `-p`, `--port`          | `6881`                | Porta TCP local informada ao tracker durante o anúncio.                                         |
| `--auto-resume`         | `False`               | Faz a leitura e validação SHA-1 de arquivos existentes no destino antes de baixar.              |
| `--info`                | `False`               | Exibe os metadados do torrent formatados e encerra sem iniciar download.                        |
| `-v`, `--verbose`       | `False`               | Habilita logs detalhados em nível `DEBUG`.                                                      |

---

## Executando a Suíte de Testes

O projeto inclui uma suíte abrangente cobrindo testes unitários, testes de segurança e testes de integração com simuladores locais de Tracker HTTP e Peers BitTorrent.

Para executar todos os testes usando o runner nativo do Python:

```bash
python -m unittest discover -s tests
```

Para executar um arquivo de teste específico:

```bash
# Testes do parser Bencode
python -m unittest tests/test_bencode.py

# Testes da estratégia Rare Piece First
python -m unittest tests/test_rarest_first.py

# Testes de integração ponta a ponta
python -m unittest tests/test_integration.py

# Testes de segurança e robustez
python -m unittest tests/test_security.py
```

Se você tiver o `pytest` instalado no seu ambiente, também pode executar:

```bash
pytest -v
```

---

## Limitações Conhecidas e Fora de Escopo

Por se tratar de um cliente educacional focado em conformidade, legibilidade e pureza de dependências, algumas extensões avançadas do ecossistema BitTorrent estão intencionalmente fora do escopo atual:

1. **Trackers UDP (BEP 0015)**: O cliente suporta exclusivamente trackers HTTP e HTTPS. Torrents que dependem unicamente de URLs `udp://` não obterão peers pelo tracker.
2. **DHT / Distributed Hash Table (BEP 0005)**: O cliente não implementa o protocolo Kademlia DHT para *trackerless torrents* (Magnet Links sem tracker).
3. **uTP / Micro Transport Protocol (BEP 0029)**: Conexões de rede são realizadas estritamente sobre sockets TCP convencionais (sem suporte a UDP framing do uTP).
4. **Criptografia de Protocolo (MSE / PE)**: Conexões com peers que exigem criptografia de cabeçalho obrigatória serão recusadas durante o handshake.
5. **Algoritmo de Choking Local Dinâmico (Choking / Seeding Ativo)**: O foco principal do cliente é o *download* e montagem confiável de dados. Embora o cliente responda ao handshake, envie mensagens `Have` e notifique o tracker com `completed`, ele não implementa algoritmos de *tit-for-tat* para upload contínuo a outros leechers.
