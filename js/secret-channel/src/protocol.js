const b4a = require('b4a')

/**
 * @typedef {import("./types").B4A} B4A
 * @typedef {import("./types").Crypt} Crypt
 */

const {
  KEY_SIZE,
  NONCE_SIZE,
  LENGTH_OR_END_PLAINTEXT,
  LENGTH_OR_END_CIPHERTEXT,
} = require('./constants')

class Encrypter {
  /**
   * @type {Crypt}
   */
  #crypto

  /**
   * @type {B4A | null}
   */
  #key

  /**
   * @type {B4A}
   */
  #nonce

  /**
   * @param {Crypt} crypto
   * @param {B4A} key
   * @param {B4A} nonce
   */
  constructor(crypto, key, nonce) {
    this.#crypto = crypto

    if (!b4a.isBuffer(key)) {
      throw new Error('secret-channel/Encrypter: key must be a buffer')
    }
    if (key.length !== KEY_SIZE) {
      throw new Error(`secret-channel/Encrypter: key must be ${KEY_SIZE} bytes`)
    }
    this.#key = key

    if (!b4a.isBuffer(nonce)) {
      throw new Error('secret-channel/Encrypter: nonce must be a buffer')
    }
    if (nonce.length !== NONCE_SIZE) {
      throw new Error(`secret-channel/Encrypter: nonce must be ${NONCE_SIZE} bytes`)
    }
    // clone the nonce so is owned and mutable
    this.#nonce = b4a.allocUnsafe(NONCE_SIZE)
    b4a.copy(nonce, this.#nonce)
  }

  /**
   * @param {B4A} plaintext
   * @returns {[B4A, B4A]}
   */
  next(plaintext) {
    const plaintextBuffer = b4a.from(plaintext)
    const length = this.#chunkLength(plaintextBuffer.length)
    const content = this.#chunkContent(plaintextBuffer)
    return [length, content]
  }

  /**
   * @returns {B4A}
   */
  end() {
    const eos = this.#chunkEndOfStream()
    this.#key = null
    return eos
  }

  /**
   * @param {number} length
   * @returns {B4A}
   */
  #chunkLength(length) {
    const lengthData = b4a.allocUnsafe(LENGTH_OR_END_PLAINTEXT)
    const lengthDataView = new DataView(lengthData.buffer, lengthData.byteOffset, lengthData.length)
    lengthDataView.setInt16(0, length, false)
    return this.#encrypt(lengthData)
  }

  /**
   * @param {B4A} content
   * @returns {B4A}
   */
  #chunkContent(content) {
    return this.#encrypt(content)
  }

  /**
   * @return {B4A}
   */
  #chunkEndOfStream() {
    const eos = b4a.alloc(LENGTH_OR_END_PLAINTEXT, 0)
    return this.#encrypt(eos)
  }

  /**
   * @param {B4A} bytes
   * @returns {B4A}
   */
  #encrypt(bytes) {
    if (this.#key === null) {
      throw new Error('secret-channel/Encrypter: stream has already ended')
    }
    const ciphertext = this.#crypto.encrypt(this.#key, this.#nonce, bytes)
    this.#crypto.increment(this.#nonce)
    return ciphertext
  }
}

/**
 * @typedef {{
 *  type: 'length'
 *  length: number
 * } | {
 *  type: 'end-of-stream'
 * }} LengthOrEnd
 */

class Decrypter {
  /**
   * @type {Crypt}
   */
  #crypto

  /**
   * @type {B4A | null}
   */
  #key

  /**
   * @type {B4A}
   */
  #nonce

  /**
   * @param {Crypt} crypto
   * @param {B4A} key
   * @param {B4A} nonce
   */
  constructor(crypto, key, nonce) {
    this.#crypto = crypto

    if (!b4a.isBuffer(key)) {
      throw new Error('secret-channel/Decrypter: key must be a buffer')
    }
    if (key.length !== KEY_SIZE) {
      throw new Error(`secret-channel/Decrypter: key must be ${KEY_SIZE} bytes`)
    }
    this.#key = key

    if (!b4a.isBuffer(nonce)) {
      throw new Error('secret-channel/Decrypter: nonce must be a buffer')
    }
    if (nonce.length !== NONCE_SIZE) {
      throw new Error(`secret-channel/Encrypter: nonce must be ${NONCE_SIZE} bytes`)
    }
    // clone the nonce so is owned and mutable
    this.#nonce = b4a.allocUnsafe(NONCE_SIZE)
    b4a.copy(nonce, this.#nonce)
  }

  /**
   * @param {B4A} ciphertext
   * @returns {LengthOrEnd}
   */
  lengthOrEnd(ciphertext) {
    if (ciphertext.length !== LENGTH_OR_END_CIPHERTEXT) {
      throw new Error(
        `secret-channel/Decrypter: length / end ciphertext must be ${LENGTH_OR_END_CIPHERTEXT} bytes`,
      )
    }

    const plaintext = this.#decrypt(ciphertext)

    if (this.#crypto.isZero(plaintext)) {
      // delete the key
      this.#key = null
      return {
        type: 'end-of-stream',
      }
    }

    const lengthData = plaintext
    const lengthDataView = new DataView(lengthData.buffer, lengthData.byteOffset, lengthData.length)
    const length = lengthDataView.getInt16(0, false)
    return {
      type: 'length',
      length,
    }
  }

  /**
   * @param {B4A} ciphertext
   * @returns {B4A}
   */
  content(ciphertext) {
    return this.#decrypt(ciphertext)
  }

  /**
   * @param {B4A} bytes
   * @returns {B4A}
   */
  #decrypt(bytes) {
    if (this.#key === null) {
      throw new Error('secret-channel/Decrypter: stream has already ended')
    }
    const plaintext = this.#crypto.decrypt(this.#key, this.#nonce, bytes)
    this.#crypto.increment(this.#nonce)
    return plaintext
  }
}

/**
 * @param {Crypt} crypto
 * @returns {{
 *   createEncrypter: (key: B4A, nonce: B4A) => Encrypter
 *   createDecrypter: (key: B4A, nonce: B4A) => Decrypter
 * }}
 */
function protocol(crypto) {
  return {
    createEncrypter(key, nonce) {
      return new Encrypter(crypto, key, nonce)
    },
    createDecrypter(key, nonce) {
      return new Decrypter(crypto, key, nonce)
    },
  }
}

module.exports = protocol
