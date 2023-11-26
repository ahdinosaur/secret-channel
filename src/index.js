const { concatBytes } = require('@noble/ciphers/utils')

const { createCipher } = require('./crypto')

const KEY_SIZE = 32
const TAG_SIZE = 16

const NONCE_SIZE = 12
const LENGTH_SIZE = 2
const COUNTER_MAX = 2n ** 64n

class StreamCounter {
  #sequence
  #nonce
  #nonceDataView

  constructor() {
    this.#sequence = 0n
    this.#nonce = new Uint8Array(NONCE_SIZE)
    this.#nonceDataView = new DataView(this.#nonce.buffer)
  }

  next_nonce() {
    if (this.#sequence >= COUNTER_MAX) {
      throw new Error('secret-channel/StreamNonce: reached counter maximum')
    }

    this.#nonceDataView.setBigUint64(0, this.#sequence, true)

    this.#sequence++

    return this.#nonce
  }
}

class StreamEncrypter {
  #key
  #counter

  constructor(key) {
    if (key.byteLength !== KEY_SIZE) {
      throw new Error(`secret-channel/StreamEncrypter: key must be ${KEY_SIZE} bytes`)
    }
    this.#key = key

    this.#counter = new StreamCounter()
  }

  next(plaintext) {
    const length = this.#chunkLength(plaintext.byteLength)
    const content = this.#chunkContent(plaintext)
    return concatBytes(length, content)
  }

  end() {
    const eos = this.#chunkEndOfStream()
    // TODO delete the key
    return eos
  }

  #chunkLength(length) {
    const lengthData = new Uint8Array(LENGTH_SIZE)
    const lengthDataView = new DataView(lengthData.buffer)
    lengthDataView.setInt16(0, length, true)
    return this.#encrypt(lengthData)
  }

  #chunkContent(content) {
    return this.#encrypt(content)
  }

  #chunkEndOfStream() {
    const eos = new Uint8Array(LENGTH_SIZE).fill(0)
    return this.#encrypt(eos)
  }

  #encrypt(bytes) {
    const nonce = this.#counter.next_nonce()
    const cipher = createCipher(this.#key, nonce)
    return cipher.encrypt(bytes)
  }
}

/*
class StreamDecrypter {
  constructor(key, nonce, options) {}
}
*/

module.exports = {
  StreamEncrypter,
  KEY_SIZE,
  TAG_SIZE,
}
