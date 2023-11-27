const b4a = require('b4a')
const test = require('node:test')
const assert = require('node:assert')
const { randomBytes } = require('node:crypto')

const { createEncrypter, createDecrypter, KEY_SIZE, NONCE_SIZE } = require('../')

test('roundtrip hello world', async (t) => {
  // generate a random secret, `KEY_SIZE` bytes long
  const key = randomBytes(KEY_SIZE)
  const nonce = randomBytes(NONCE_SIZE)

  const contentPlaintext1 = b4a.from('hello')
  const contentPlaintext2 = b4a.from('world')

  const encrypter = createEncrypter(key, nonce)
  const decrypter = createDecrypter(key, nonce)

  const [lengthCiphertext1, contentCiphertext1] = encrypter.next(contentPlaintext1)
  const [lengthCiphertext2, contentCiphertext2] = encrypter.next(contentPlaintext2)
  const eosCiphertext = encrypter.end()

  const lengthDecrypted1 = decrypter.lengthOrEnd(lengthCiphertext1)
  assert.equal(lengthDecrypted1.type, 'length')
  assert.equal(lengthDecrypted1.length, contentPlaintext1.length)

  const contentDecrypted1 = decrypter.content(contentCiphertext1)
  assert(b4a.equals(contentDecrypted1, contentPlaintext1))

  const lengthDecrypted2 = decrypter.lengthOrEnd(lengthCiphertext2)
  assert.equal(lengthDecrypted2.type, 'length')
  assert.equal(lengthDecrypted2.length, contentPlaintext2.length)

  const contentDecrypted2 = decrypter.content(contentCiphertext2)
  assert(b4a.equals(contentDecrypted2, contentPlaintext2))

  const eosDecrypted = decrypter.lengthOrEnd(eosCiphertext)
  assert.equal(eosDecrypted.type, 'end-of-stream')
})
