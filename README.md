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

- Stream truncation: avoided by checking for "end-of-stream" as the final chunk.
- Chunk removal: the wrong nonce would be used, producing an AEAD decryption error.
- Chunk reordering: the wrong nonce would be used, producing an AEAD decryption error.
- Chunk duplication: the wrong nonce would be used, producing an AEAD decryption error.
- Chunk modification: this is what an AEAD is designed to detect.

## Specification

See [SPEC.md](./SPEC.md)

## Packages

### JavaScript

[![ci status](https://img.shields.io/github/actions/workflow/status/ahdinosaur/secret-channel/node.js.yml?style=flat-square)](https://github.com/ahdinosaur/secret-channel/actions/workflows/node.js.yml?query=branch%3Amain)

#### Protocol

[`secret-channel`](./js/secret-channel)

#### Pull Stream

TODO

#### Node Stream

TODO

### Rust

#### Protocol

TODO

#### Async Stream

TODO
