# "Secret Channel" Specification 🤫

Streaming authenticated encryption using ChaCha20-Poly1305 ([RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439)).

## Pre-requisites

- The channel must be reliable and ordered: i.e. TCP.
- Each channel key must be an ephemeral key for a single channel and discarded when the channel ends.
  - To get an ephemeral key for a session, do a secure key exchange, such as [Noise](https://noiseprotocol.org/noise.html) or [Secret Handshake](https://dominictarr.github.io/secret-handshake-paper/shs.pdf) first.
  - For a duplex (bi-directional) connection between peers, create two secret channels (with separate keys), one in each direction.
- A (key, nonce) pair must NEVER be re-used.

## Security Guarantees

`secret-channel` protects the stream from:

- Stream truncation: avoided by checking for "end-of-stream" as the final chunk.
- Chunk removal: the wrong nonce would be used, producing an AEAD decryption error.
- Chunk reordering: the wrong nonce would be used, producing an AEAD decryption error.
- Chunk duplication: the wrong nonce would be used, producing an AEAD decryption error.
- Chunk modification: this is what an AEAD is designed to detect.

## Stream

Data is sent over the channel in chunks.

- Either ([Length](#length-chunk), [Content](#content-chunk)) chunk pairs,
- or a single ([End-of-stream](#end-of-stream-chunk)) chunk.

Each chunk MUST be encrypted with a unique [nonce](#nonces).

```txt
+---------------------+-------------------------------------------------------+
|    length chunk     |       content chunk       | ... | end-of-stream chunk |
+---------------------+---------------------------+-----+---------------------+
| 2B length + 16B tag | variable length + 16B tag | ... | 2B zeros + 16B tag  |
+---------------------+---------------------------+-----+---------------------+
```

### Nonces

ChaCha20-Poly1305 requires a 12-byte (96-bit) nonce.

We must ensure both random and unique nonces over the channel session.

We start with a preset (random) 12-byte (96-bit) nonce, provided when creating the stream.

After each chunk, we increment the 12-byte (96-bit) nonce as a little-endian unsigned integer.

To increment a 12-byte little-endian unsigned integer, see [libsodium `increment`](https://doc.libsodium.org/helpers#incrementing-large-numbers), or the following JavaScript code:

```js
function increment(buf) {
  let c = 1
  for (let i = 0; i < buf.length; i++) {
    c += buf[i]
    buf[i] = c
    c >>= 8
  }
}
```

### Chunks

#### Length chunk

We start with a length chunk, seen here in plaintext:

```txt
2 byte length (plaintext):
+---------------+
|     length    |
+---------------+
|  2B (u16_be)  |
+---------------+
```

The length is a 16-bits unsigned integer (encoded as big-endian).

(The maximum content length is 2^16 bytes or 65,536 bytes or 65.536 Kb)

A length of `0` is not a valid length. (And instead refers to a [End-of-stream chunk](#end-of-stream-chunk))

We encrypt and authenticate the length with ChaCha20-Poly1305 into the following ciphertext:

```txt
18 byte length (ciphertext):
+------------------+------------+
| encrypted length |  auth tag  |
+------------------+------------+
|        2B        |    16B     |
+------------------+------------+
```

#### Content chunk

A content chunk is simply the content.

From 0 to 2^16 (65,536) bytes. (Matching the length in the previous chunk.)

If content is larger than 2^16 (65,536) bytes, split the bytes across multiple chunks.

```txt
Variable length content (plaintext):
+-----------------+
|    content      |
+-----------------+
| variable length |
+-----------------+
```

Then encrypted and authenticated with ChaCha20-Poly1305.

```txt
Variable length content (ciphertext):
+----------------------+------------+
| content (ciphertext) |  auth tag  |
+----------------------+------------+
|    variable length   |    16B     |
+----------------------+------------+
```

### End-of-stream chunk

A end-of-stream chunk is 2 bytes (the size of a [Length chunk](#length-chunk)) of all zeros.

```txt
2 byte end-of-stream (plaintext):
+---------------+
| end-of-stream |
+---------------+
|   2B zeros    |
+---------------+
```

Then encrypted and authenticated with ChaCha20-Poly1305.

```txt
18 byte end-of-stream (ciphertext):
+-----------------+------------+
| encrypted zeros |  auth tag  |
+-----------------+------------+
|        2B       |    16B     |
+-----------------+------------+
```

## Comparisons

### Scuttlebutt's Box Stream

Secret Channel is meant to be a successor to Scuttlebutt's [Box Stream](https://ssbc.github.io/scuttlebutt-protocol-guide/#box-stream).

A few similarities:

- Box Stream and Secret Channel both use a preset (random) nonce to start and then increment after each chunk.
- Box Stream and Secret Channel both have length and content chunks.

A few differences:

- Box Stream increments the nonce as a big-endian unsigned integer.
  - Secret Channel increments the nonce as little-endian, to be compatible with `libsodium.increment` and more favorable to most CPU architectures.
- Box Stream uses `libsodium.crypto_secretbox_easy` and `libsodium.crypto_secretbox_open_easy`, which uses XSalsa20-Poly1305.
  - Secret Channel uses ChaCha20-Poly1305 (the successor to Salsa20-Poly1305) as an AEAD directly.
- Box Stream appends the authentication tag of the encrypted content into the plaintext of the length chunk.

### Libsodium's secretstream

Libsodium's secretstream is designed to be extra safe and resistant to developer misuse.

Libsodium's secretstream has more features not included in Secret Channel:

- secretstream is a chunked message stream, where each message has a tag: `TAG_MESSAGE`, `TAG_FINAL`, `TAG_PUSH`, and `TAG_REKEY`
- secretstream uses HChaCha20 to derive a subkey and takes the last 64 bits of the nonce as the nonce for encryption.
  - This nonce is stored/sent as a header from the encrypter to the decrypter at the beginning of the stream.
- secretstream uses a 32-bit counter starting at 1 that is prepended to the 64-bit nonce
  - After every message, the 64-bit nonce becomes the nonce XOR the first 64 bits of the Poly1305 tag.
  - If the counter is 0, the stream will automatically re-key
- secretstream gives no guidance on how to handle variable length messages.
  - Libsodium provides functions `sodium_pad` and `sodium_unpad` to pad messages to fixed lengths.

Both secretstream and Secret Channel use ChaCha20-Poly1305 for encryption.

secretstream has affordances that Secret Channel doesn't need:

- By sending the initial nonce as a header, secretstream doesn't require the encrypter and decrypter to have a shared initial nonce.
  - Secret Channel is designed for a use with Secret Handshake where we already have a way to generate a shared initial nonce.
- By using a 64-bit random nonce with a 32-bit counter, secretstream is more safe to re-use keys???
  - Secret Channel explicitly disallows any key re-use.
- By XOR'ing the nonce with the previous Poly1305 tag, secretstream is more safe ...???
  - This also prevents random-access decryption.

### STREAM + ChaCha20-Poly1305

STREAM is designed to avoid nonce-reuse in practical settings where keys may be re-used.

- STREAM is a pattern of using any AEAD as a stream of messages.
- STREAM encodes the last message with a tag in the AD.
- STREAM creates each nonce from a random 64-bit prefix and a 32-bit counter.
  - The likelihood of a collision, even when re-using keys, is considered safe enough.
  - Secret Channel avoids this problem by explicitly disallowing any key re-use.
- STREAM gives no guidance on how to handle variable length messages.

## References

- [STREAM: "Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance"](https://eprint.iacr.org/2015/189.pdf).
- [Rust implementation of STREAM](https://docs.rs/aead/latest/aead/stream/index.html)
- [StackExchange post on streaming authenticated encryption](https://crypto.stackexchange.com/a/106992)
- [shadowsocks SIP022 AEAD-2022](https://github.com/shadowsocks/shadowsocks-org/blob/main/docs/doc/sip022.md)
- [libsodium: Encrypting a set of related messages](https://libsodium.gitbook.io/doc/secret-key_cryptography/encrypted-messages)
- [ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)](https://www.rfc-editor.org/rfc/rfc7905)
- [The Security of ChaCha20-Poly1305 in the Multi-user Setting](https://eprint.iacr.org/2023/085.pdf)
