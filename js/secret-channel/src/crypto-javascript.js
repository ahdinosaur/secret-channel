const { chacha20poly1305 } = require('@noble/ciphers/chacha')

const debug = require('./debug')

/**
 * @typedef {import('./types').B4A} B4A
 */

module.exports = {
  encrypt,
  decrypt,
  increment,
  isZero,
}

/**
 * @param {B4A} keyArg
 * @param {B4A} nonceArg
 * @param {B4A} plaintextArg
 * @returns {B4A}
 */
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

/**
 * @param {B4A} key
 * @param {B4A} nonce
 * @param {B4A} ciphertext
 * @returns {B4A}
 */
function decrypt(key, nonce, ciphertext) {
  return chacha20poly1305(key, nonce).encrypt(ciphertext)
}

/**
 * @param {B4A} buf
 * @returns {void}
 */
function increment(buf) {
  const len = buf.length
  let c = 1
  for (let i = 0; i < len; i++) {
    c += buf[i]
    buf[i] = c
    c >>= 8
  }
}

/**
 * @param {B4A} buf
 * @returns {boolean}
 */
function isZero(buf) {
  const len = buf.length
  let d = 0
  for (let i = 0; i < len; i++) d |= buf[i]
  return d === 0
}
