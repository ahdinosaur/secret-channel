# `secret-channel`

[![npm version](https://img.shields.io/npm/v/secret-channel.svg?style=flat-square)](https://www.npmjs.com/package/secret-channel) [![npm downloads](https://img.shields.io/npm/dt/secret-channel?style=flat-square)](https://www.npmjs.com/package/secret-channel) [![ci status](https://img.shields.io/github/actions/workflow/status/ahdinosaur/secret-channel/node.js.yml?style=flat-square)](https://github.com/ahdinosaur/secret-channel/actions/workflows/node.js.yml?query=branch%3Amain)

Streaming authenticated encryption using ChaCha20-Poly1305 ([RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439)) (or other [AEAD constructions](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead)).

See [project README.md](../../README.md) for more information.

## Install

```shell
npm install --save secret-channel
```

## API

### `encrypter = createEncrypter(key)`

### `[lengthCiphertext, contentCiphertext] = encrypter.next(plaintext)`

### `endCiphertext = encrypter.end()`

### `decrypter = createDecrypter(key)`

### `lengthOrEnd = decrypter.lengthOrEnd(ciphertext)`

`lengthOrEnd` is either:

```js
{
  type: 'length',
  length // number
}
```

or

```js
{
  type: 'end-of-stream',
}
```

### `content = decrypter.content(ciphertext)`

### `KEY_SIZE`

The size of a ChaCha20-Poly1305 key: 32 bytes

### `TAG_SIZE`

The size of ChaCha20-Poly1305 authentication tag: 16 bytes.

The size of encrypted ciphertext is `plaintext.length + TAG_SIZE`.

The size of decrypted plaintext is `ciphertext.length - TAG_SIZE`.

### `LENGTH_OR_END_PLAINTEXT`

2 bytes

### `LENGTH_OR_END_CIPHERTEXT`

18 bytes (`LENGTH_OR_END_PLAINTEXT + TAG_SIZE`)

### `MAX_CONTENT_LENGTH`

$`2^{16} - 1`$

## Example

### Encryption

```js
const b4a = require('b4a')
const { createEncrypter, KEY_SIZE } = require('secret-channel')

// with a new secret key of size `KEY_SIZE`
const encrypter = createEncrypter(key)

const bufferList = []
bufferList.push(encrypter.next('hello'))
bufferList.push(encrypter.next('world'))
bufferList.push(encrypter.end())

const bytes = b4a.concat(bufferList)

// send bytes
```

#### Decryption

```js
const { createDecrypter, KEY_SIZE, TAG_SIZE, LENGTH_OR_END_CIPHERTEXT } = require('secret-channel')

// const key = ...

const decrypter = createDecrypter(key)

// receive lengthOrEndBytes of size `LENGTH_OR_END_CIPHERTEXT`

const lengthOrEnd = decrypter.lengthOrEnd(lengthOrEndBytes)
if (lengthOrEnd.type === 'end-of-stream') {
  // end of stream
} else if (lengthOrEnd.type === 'length') {
  const length = lengthOrEnd.length

  // receive contentBytes of size `length + TAG_SIZE`

  const content = decrypter.content(contentBytes)
}

// and so on...
```

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
