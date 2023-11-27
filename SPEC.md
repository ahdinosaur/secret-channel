# "Secret Channel" Specification

## Pre-requisites

- The channel must be reliable and ordered: i.e. TCP.
- Each channel key must be an ephemeral key for a single channel and discarded when the channel ends.
- A (key, nonce) pair must NEVER be re-used.

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
  const len = buf.length
  let c = 1
  for (let i = 0; i < len; i++) {
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

## References

- [STREAM: "Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance"](https://eprint.iacr.org/2015/189.pdf).
- [Rust implementation of STREAM](https://docs.rs/aead/latest/aead/stream/index.html)
- [StackExchange post on streaming authenticated encryption](https://crypto.stackexchange.com/a/106992)
- [shadowsocks SIP022 AEAD-2022](https://github.com/shadowsocks/shadowsocks-org/blob/main/docs/doc/sip022.md)
- [libsodium: Encrypting a set of related messages](https://libsodium.gitbook.io/doc/secret-key_cryptography/encrypted-messages)
- [ChaCha20-Poly1305 Cipher Suites for Transport Layer Security (TLS)](https://www.rfc-editor.org/rfc/rfc7905)
