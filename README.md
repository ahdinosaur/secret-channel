# "Secret Channel" 🤫

> Streaming authenticated encryption using ChaCha20-Poly1305 ([RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439)) (or other [AEADs](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead)).

A protocol for a secure message stream, after you've done a [secure key exchange](https://github.com/ahdinosaur/secret-handshake).

![Fig 7 Le Telephone by T du Moncel Paris 1880](./tin-can-telephone.jpg)

(Note: This protocol has not been audited to be safe. Use at your own risk.)

## Specification

See [SPEC.md](./SPEC.md)

## Packages

### JavaScript

[![ci status](https://img.shields.io/github/actions/workflow/status/ahdinosaur/secret-channel/node.js.yml?style=flat-square)](https://github.com/ahdinosaur/secret-channel/actions/workflows/node.js.yml?query=branch%3Amain)

#### Protocol: [`secret-channel`](./js/secret-channel)

[![npm version](https://img.shields.io/npm/v/secret-channel.svg?style=flat-square)](https://www.npmjs.com/package/secret-channel) [![npm downloads](https://img.shields.io/npm/dt/secret-channel?style=flat-square)](https://www.npmjs.com/package/secret-channel)

#### Pull Stream: [`pull-secret-channel`](./js/pull-secret-channel)

[![npm version](https://img.shields.io/npm/v/pull-secret-channel.svg?style=flat-square)](https://www.npmjs.com/package/pull-secret-channel) [![npm downloads](https://img.shields.io/npm/dt/pull-secret-channel?style=flat-square)](https://www.npmjs.com/package/pull-secret-channel)

#### Node Stream

TODO

### Rust

#### Protocol

TODO

#### Async Stream

TODO
