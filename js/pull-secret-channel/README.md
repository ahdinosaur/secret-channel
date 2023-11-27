# `pull-secret-channel`

[![npm version](https://img.shields.io/npm/v/pull-secret-channel.svg?style=flat-square)](https://www.npmjs.com/package/pull-secret-channel) [![npm downloads](https://img.shields.io/npm/dt/pull-secret-channel?style=flat-square)](https://www.npmjs.com/package/pull-secret-channel) [![ci status](https://img.shields.io/github/actions/workflow/status/ahdinosaur/secret-channel/node.js.yml?style=flat-square)](https://github.com/ahdinosaur/secret-channel/actions/workflows/node.js.yml?query=branch%3Amain)

Streaming authenticated encryption using ChaCha20-Poly1305 ([RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439)) (or other [AEAD constructions](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead)).

See [project README.md](../../README.md) for more information.

## Install

```shell
npm install --save pull-secret-channel
```

## Example

```js
const { randomBytes } = require('crypto')
const pull = require('pull-stream')
const { KEY_SIZE, pullEncrypter, pullDecrypter } = require('pull-secret-channel')

// generate a random secret, `KEY_SIZE` bytes long.
const key = randomBytes(KEY_SIZE)

const plaintext1 = Buffer.from('hello world')

pull(
  pull.values([plaintext1]),

  // encrypt every byte
  pullEncrypter(key),

  // the encrypted stream
  pull.through((ciphertext) => {
    console.log('Encrypted: ', ciphertext)
  }),

  // decrypt every byte
  pullDecrypter(key),

  pull.concat((err, plaintext2) => {
    if (err) throw err
    console.log('Decrypted: ', plaintext2)
  }),
)
```

## API

### `pullEncrypter(key)`

Returns a "through" pull-stream.

For every plaintext content item in stream:

- Constructs and encrypts content length
- Encrypts content

And when stream done, constructs and encrypts an end-of-stream message.

### `pullDecrypter(key)`

Returns a "through" pull-stream.

First reads and decrypts either a length or end-of-stream message.

If end-of-stream message, gracefully ends the stream.

Otherwise length message, so reads and decrypts the specified content.

If stream ends without end-of-stream message, aborts with an error.

### `KEY_SIZE`

The size of a ChaCha20-Poly1305 key: 32 bytes

### `TAG_SIZE`

The size of ChaCha20-Poly1305 authentication tag: 16 bytes.

The size of encrypted ciphertext is `plaintext.length + TAG_SIZE`.

The size of decrypted plaintext is `ciphertext.length - TAG_SIZE`.

## License

```txt
Copyright 2023 Michael Williams

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
