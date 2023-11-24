# secret-channel

_Work in progress_

Streaming authenticated encryption using ChaCha20-Poly1305 ([RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439)) (or other [AEAD constructions](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead)).

`secret-channel` is designed to be easy to implement and provide [security guarantees](#security-guarantees) (if you abide by the [pre-requisites](#pre-requisites)).

(Note: This has not been audited to be safe. Use at your own risk.)

## Pre-requisites

- The channel must be reliable and ordered: i.e. TCP.
- Each channel key must be an ephemeral key for a single channel and discarded when the channel ends.
    - To get an ephemeral key for a session, you should do a secure key exchange, such as [`secret-handshake`](https://github.com/auditdrivencrypto/secret-handshake).
- For a duplex (bi-directional) connection between peers, you should create two secret channels (with separate keys), one in each direction.
- A (key, nonce) pair must NEVER be re-used.

## Security Guarantees

`secret-channel` protects the stream from:

- Stream truncation: avoided by checking for the "goodbye" tag in the final header chunk.
- Chunk removal: the wrong nonce would be used, producing an AEAD decryption error.
- Chunk reordering: the wrong nonce would be used, producing an AEAD decryption error.
- Chunk duplication: the wrong nonce would be used, producing an AEAD decryption error.
- Chunk modification: this is what an AEAD is designed to detect.

## Stream

```txt
+--------------------------+------------------------------------------------------------+
|  header (content) chunk  |       content chunk       | ... |  header (goodbye) chunk  |
+--------------------------+---------------------------+-----+--------------------------+
| 2B type/length + 16B tag | variable length + 16B tag | ... | 2B type/length + 16B tag |
+--------------------------+---------------------------+-----+--------------------------+
```

```mermaid
flowchart LR
    h0 --> c1 --> h2 --> c3 --> g4

    subgraph h0 [first header]
        direction TB
        P0["Plaintext"]
        Ek0["Encrypt"]
        Ci0["Ciphertext"]
        P0 --> Ek0 --> Ci0

        Co0["Counter = 0"] --> N0
        N0["Nonce"] --> Ek0

        L0["Length = 6"] --> P0
        T0["Type = Content"] --> P0
    end

    subgraph c1 [first content]
        direction TB
        P1["Plaintext"]
        Ek1["Encrypt"]
        Ci1["Ciphertext"]

        Co1["Counter = 1"] --> N1
        N1["Nonce"] --> Ek1
        L1["Content = #quot;Hello #quot;"] --> P1
        P1 --> Ek1 --> Ci1
    end

    subgraph h2 [second header]
        direction TB
        P2["Plaintext"]
        Ek2["Encrypt"]
        Ci2["Ciphertext"]
        P2 --> Ek2 --> Ci2

        Co2["Counter = 2"] --> N2
        N2["Nonce"] --> Ek2

        L2["Length = 8"] --> P2
        T2["Type = Content"] --> P2
    end

    subgraph c3 [second content]
        direction TB
        P3["Plaintext"]
        Ek3["Encrypt"]
        Ci3["Ciphertext"]

        Co3["Counter = 3"] --> N3
        N3["Nonce"] --> Ek3
        L3["Content = #quot;World!!!#quot;"] --> P3
        P3 --> Ek3 --> Ci3
    end

    subgraph g4 [goodbye]
        direction TB
        P4["Plaintext"]
        Ek4["Encrypt"]
        Ci4["Ciphertext"]
        P4 --> Ek4 --> Ci4

        Co4["Counter = 4"] --> N4
        N4["Nonce"] --> Ek4

        L4["Length = 0"] --> P4
        T4["Type = Goodbye"] --> P4
    end
```

## Example

TODO

```shell
```

## Design

Data is sent over the channel in chunks.

- Either (Length Header, Content) chunk pairs,
- or a single (Goodbye Header) chunk.

Each chunk MUST have a unique nonce.

### Nonces

To ensure unique nonces over the channel session, we will use a simple counter.

The counter starts at 0 and increments by 1 with every chunk.

(This is okay because 1) we will never re-use a key, and 2) a 256-bit key protects against [batch/multi-target attacks](https://blog.cr.yp.to/20151120-batchattacks.html).)

Since the ChaCha20-Poly1305 nonce is 12 bytes (96-bits), we will use a 64-bit unsigned integer as our counter sequence number.

The 64-bit counter sequence number is encoded to the 96-bit nonce as follows:

```txt
nonce:
+-----------------+-------------+
| sequence number |   padding   |
+-----------------+-------------+
|   8B (u64_le)   | 4B (0x0000) |
+-----------------+-------------+
```

If the counter sequence number overflows, the channel MUST end. (This is not expected to happen.)

### Chunks

#### Header

We start with a header chunk, seen here in plaintext:

```txt
2 byte header (plaintext):
+---------------+
| type + length |
+---------------+
|  2B (u16_le)  |
+---------------+
```

The header is a 16-bits unsigned integer (encoded as little-endian).

The type is encoded as the most-significant bit:

- `CONTENT`: `0`
- `GOODBYE`: `1`

If `CONTENT`, the length of the content is the remaining 15 bits.

```
type_and_length = length | (type << 15)
```

(The maximum content length is 32,768 bytes or 32.768 Kb)

We encrypt and authenticate the header into the following ciphertext:

```txt
18 byte header (ciphertext):
+------------------+------------+
| encrypted header |  auth tag  |
+------------------+------------+
|        2B        |    16B     |
+------------------+------------+
```

#### Content

A content chunk is simply the content, encrypted.

From 0 to 32,768 bytes.

```txt
Variable length content (plaintext):
+-----------------+
|    content      |
+-----------------+
| variable length |
+-----------------+
```

```txt
Variable length content (ciphertext):
+----------------------+------------+
| content (ciphertext) |  auth tag  |
+----------------------+------------+
|    variable length   |    16B     |
+----------------------+------------+
```

## References

- [STREAM: "Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance"](https://eprint.iacr.org/2015/189.pdf).
- [Rust implementation of STREAM](https://docs.rs/aead/latest/aead/stream/index.html)
- [StackExchange post on streaming authenticated encryption](https://crypto.stackexchange.com/a/106992)
- [shadowsocks SIP022 AEAD-2022](https://github.com/shadowsocks/shadowsocks-org/blob/main/docs/doc/sip022.md)
- [libsodium: Encrypting a set of related messages](https://libsodium.gitbook.io/doc/secret-key_cryptography/encrypted-messages)
- [ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)](https://www.rfc-editor.org/rfc/rfc7905)
