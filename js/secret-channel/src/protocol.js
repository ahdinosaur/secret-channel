const b4a = require('b4a')

const { KEY_SIZE, LENGTH_OR_END_PLAINTEXT, LENGTH_OR_END_CIPHERTEXT } = require('./constants')

const NONCE_SIZE = 12

class StreamCounter {
  #increment
  #nonce

  constructor(increment) {
    this.#increment = increment
    this.#nonce = b4a.alloc(NONCE_SIZE, 0)
  }

  next() {
    this.#increment(this.#nonce)
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

    this.#counter = new StreamCounter(crypto.increment)
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
    const lengthData = b4a.allocUnsafe(LENGTH_OR_END_PLAINTEXT)
    const lengthDataView = new DataView(lengthData.buffer, lengthData.byteOffset, lengthData.length)
    lengthDataView.setInt16(0, length, true)
    return this.#encrypt(lengthData)
  }

  #chunkContent(content) {
    return this.#encrypt(content)
  }

  #chunkEndOfStream() {
    const eos = b4a.alloc(LENGTH_OR_END_PLAINTEXT, 0)
    return this.#encrypt(eos)
  }

  #encrypt(bytes) {
    const nonce = this.#counter.next()
    return this.#crypto.encrypt(this.#key, nonce, bytes)
  }
}

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

    this.#counter = new StreamCounter(crypto.increment)
  }

  lengthOrEnd(ciphertext) {
    if (ciphertext.length !== LENGTH_OR_END_CIPHERTEXT) {
      throw new Error(
        `secret-channel/StreamDecrypter: length / end ciphertext must be ${LENGTH_OR_END_CIPHERTEXT} bytes`,
      )
    }

    const plaintext = this.#decrypt(ciphertext)

    if (this.#crypto.isZero(plaintext)) {
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
    createEncrypter(key) {
      return new StreamEncrypter(crypto, key)
    },
    createDecrypter(key) {
      return new StreamDecrypter(crypto, key)
    },
  }
}

module.exports = protocol
