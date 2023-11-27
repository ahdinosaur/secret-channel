const b4a = require('b4a')
const { chacha20poly1305 } = require('@noble/ciphers/chacha')

const debug = require('./debug')

module.exports = {
  encrypt,
  decrypt,
  increment,
  isZero,
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

function increment(buf) {
  const len = buf.length
  let c = 1
  for (let i = 0; i < len; i++) {
    c += buf[i]
    buf[i] = c
    c >>= 8
  }
}

function isZero(buf) {
  const len = buf.length
  let d = 0
  for (let i = 0; i < len; i++) d |= buf[i]
  return d === 0
}
