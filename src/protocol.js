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

    if (key.length !== KEY_SIZE) {
      throw new Error(`secret-channel/StreamEncrypter: key must be ${KEY_SIZE} bytes`)
    }
    this.#key = key

    this.#counter = new StreamCounter()
  }

  next(plaintext) {
    const plaintextBuffer = b4a.from(plaintext)
    const length = this.#chunkLength(plaintextBuffer.length)
    const content = this.#chunkContent(plaintextBuffer)
    return [length, content]
  }

  end() {
    const eos = this.#chunkEndOfStream()
    // TODO delete the key
    return eos
  }

  #chunkLength(length) {
    const lengthData = b4a.allocUnsafe(LENGTH_SIZE)
    const lengthDataView = new DataView(lengthData.buffer, lengthData.byteOffset, lengthData.length)
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

const endOfStreamBytes = b4a.alloc(LENGTH_SIZE, 0)

class StreamDecrypter {
  #crypto
  #key
  #counter

  constructor(crypto, key) {
    this.#crypto = crypto

    if (key.length !== KEY_SIZE) {
      throw new Error(`secret-channel/StreamDecrypter: key must be ${KEY_SIZE} bytes`)
    }
    this.#key = key

    this.#counter = new StreamCounter()
  }

  lengthOrEnd(ciphertext) {
    if (ciphertext.length !== LENGTH_SIZE + TAG_SIZE) {
      throw new Error(
        `secret-channel/StreamDecrypter: length / end ciphertext must be ${
          LENGTH_SIZE + TAG_SIZE
        } bytes`,
      )
    }

    const plaintext = this.#decrypt(ciphertext)

    if (plaintext.equals(endOfStreamBytes)) {
      // TODO delete the key
      return {
        type: 'end-of-stream',
      }
    }

    const lengthData = plaintext
    const lengthDataView = new DataView(lengthData.buffer, lengthData.byteOffset, lengthData.length)
    const length = lengthDataView.getInt16(0, true)
    return {
      type: 'length',
      length,
    }
  }

  content(ciphertext) {
    return this.#decrypt(ciphertext)
  }

  #decrypt(bytes) {
    const nonce = this.#counter.next()
    return this.#crypto.decrypt(this.#key, nonce, bytes)
  }
}

function protocol(crypto) {
  return {
    createStreamEncrypter(key) {
      return new StreamEncrypter(crypto, key)
    },
    createStreamDecrypter(key) {
      return new StreamDecrypter(crypto, key)
    },
  }
}

module.exports = protocol
