const { concatBytes } = require('@noble/ciphers/utils')

const { createCipher } = require('./crypto')

const KEY_SIZE = 32
const TAG_SIZE = 16

const NONCE_SIZE = 12
const TYPELENGTH_SIZE = 2
const COUNTER_MAX = 2n ** 64n

const TYPE_CONTENT = 0
const TYPE_GOODBYE = 1

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

  next_content(plaintext) {
    const typelength = plaintext.byteLength | (TYPE_CONTENT << 15)
    const header = this.#next_header(typelength)
    const content = this.#next_content(plaintext)
    return concatBytes(header, content)
  }

  goodbye() {
    const typelength = 0 | (TYPE_GOODBYE << 15)
    const goodbye = this.#next_header(typelength)
    // TODO delete the key
    return goodbye
  }

  #next_header(typelength) {
    const header = new Uint8Array(TYPELENGTH_SIZE)
    const headerDataView = new DataView(header.buffer)
    headerDataView.setInt16(0, typelength, true)
    return this.#encrypt(header)
  }

  #next_content(plaintext) {
    return this.#encrypt(plaintext)
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
