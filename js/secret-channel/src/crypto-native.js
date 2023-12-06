const {
  // @ts-ignore
  crypto_aead_chacha20poly1305_ietf_encrypt: sodiumEncrypt,
  // @ts-ignore
  crypto_aead_chacha20poly1305_ietf_decrypt: sodiumDecrypt,
  // @ts-ignore
  crypto_aead_chacha20poly1305_ietf_ABYTES: ABYTES,
  sodium_increment: sodiumIncrement,
  sodium_is_zero: sodiumIsZero,
} = require('sodium-native')

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
 * @param {B4A} key
 * @param {B4A} nonce
 * @param {B4A} plaintext
 * @returns {B4A}
 */
function encrypt(key, nonce, plaintext) {
  debug('encrypt( %h , %h , %h )', key.slice(0, 2), nonce, plaintext)
  const ciphertext = Buffer.allocUnsafe(plaintext.length + ABYTES)
  sodiumEncrypt(ciphertext, plaintext, null, null, nonce, key)
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
  const plaintext = Buffer.allocUnsafe(ciphertext.length - ABYTES)
  sodiumDecrypt(plaintext, null, ciphertext, null, nonce, key)
  return plaintext
}

/**
 * @param {B4A} buffer
 * @returns {void}
 */
function increment(buffer) {
  // @ts-ignore
  sodiumIncrement(buffer)
}

/**
 * @param {B4A} buffer
 * @returns {boolean}
 */
function isZero(buffer) {
  // @ts-ignore
  return sodiumIsZero(buffer, buffer.length)
}
