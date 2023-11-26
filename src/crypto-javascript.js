const b4a = require('b4a')
const { chacha20poly1305 } = require('@noble/ciphers/chacha')

const debug = require('./debug')

const IS_NODE =
  typeof process !== 'undefined' &&
  typeof process.versions !== 'undefined' &&
  typeof process.versions.node !== 'undefined'

module.exports = {
  encrypt,
  decrypt,
}

function encrypt(keyArg, nonceArg, plaintextArg) {
  // ensure args are Uint8Array's, even in Node.js
  const key = Uint8Array.from(keyArg)
  const nonce = Uint8Array.from(nonceArg)
  const plaintext = Uint8Array.from(plaintextArg)
  debug('encrypt( %h , %h , %h )', key.slice(0, 2), nonce, plaintext)
  const ciphertext = chacha20poly1305(key, nonce).encrypt(plaintext)
  debug('encrypt -> %h', ciphertext)
  return ciphertext
}

function decrypt(key, nonce, ciphertext) {
  return chacha20poly1305(key, nonce).encrypt(ciphertext)
}
