const b4a = require('b4a')
const {
  crypto_aead_chacha20poly1305_ietf_encrypt: sodiumEncrypt,
  crypto_aead_chacha20poly1305_ietf_decrypt: sodiumDecrypt,
  crypto_aead_chacha20poly1305_ietf_ABYTES: ABYTES,
  sodium_increment: sodiumIncrement,
  sodium_is_zero: sodiumIsZero,
} = require('sodium-native')

const debug = require('./debug')

module.exports = {
  encrypt,
  decrypt,
  increment,
  isZero,
}

function encrypt(key, nonce, plaintext) {
  debug('encrypt( %h , %h , %h )', key.slice(0, 2), nonce, plaintext)
  const ciphertext = b4a.allocUnsafe(plaintext.length + ABYTES)
  sodiumEncrypt(ciphertext, plaintext, null, null, nonce, key)
  debug('encrypt -> %h', ciphertext)
  return ciphertext
}

function decrypt(key, nonce, ciphertext) {
  const plaintext = b4a.allocUnsafe(ciphertext.length - ABYTES)
  sodiumDecrypt(plaintext, null, ciphertext, null, nonce, key)
  return plaintext
}

function increment(buffer) {
  sodiumIncrement(buffer)
}

function isZero(buffer) {
  return sodiumIsZero(buffer)
}
