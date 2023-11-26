const b4a = require('b4a')

const { incrementBuffer } = require('./util')
const { KEY_SIZE, TAG_SIZE } = require('./constants')

const NONCE_SIZE = 12
const LENGTH_SIZE = 2

class StreamCounter {
  #nonce

  constructor() {
    this.#nonce = b4a.alloc(NONCE_SIZE, 0)
  }

  next() {
    incrementBuffer(this.#nonce)
    return this.#nonce
  }
}

class StreamEncrypter {
  #crypto
  #key
  #counter

  constructor(crypto, key) {
    this.#crypto = crypto

    if (key.byteLength !== KEY_SIZE) {
      throw new Error(`secret-channel/StreamEncrypter: key must be ${KEY_SIZE} bytes`)
    }
    this.#key = key

    this.#counter = new StreamCounter()
  }

  next(plaintext) {
    const plaintextBuffer = b4a.from(plaintext)
    const length = this.#chunkLength(plaintextBuffer.length)
    const content = this.#chunkContent(plaintextBuffer)
    return b4a.concat([length, content])
  }

  end() {
    const eos = this.#chunkEndOfStream()
    // TODO delete the key
    return eos
  }

  #chunkLength(length) {
    const lengthData = b4a.allocUnsafe(LENGTH_SIZE)
    const lengthDataView = new DataView(
      lengthData.buffer,
      lengthData.byteOffset,
      lengthData.byteLength,
    )
    lengthDataView.setInt16(0, length, true)
    return this.#encrypt(lengthData)
  }

  #chunkContent(content) {
    return this.#encrypt(content)
  }

  #chunkEndOfStream() {
    const eos = b4a.alloc(LENGTH_SIZE, 0)
    return this.#encrypt(eos)
  }

  #encrypt(bytes) {
    const nonce = this.#counter.next()
    return this.#crypto.encrypt(this.#key, nonce, bytes)
  }
}

function createStreamEncrypter(crypto, key) {
  return new StreamEncrypter(crypto, key)
}

/*
class StreamDecrypter {
  constructor(key, nonce, options) {}
}
*/

module.exports = {
  createStreamEncrypter,
  KEY_SIZE,
  TAG_SIZE,
}
