const test = require('node:test')
const assert = require('node:assert')
const pull = require('pull-stream')
const { randomBytes } = require('crypto')
const { pullEncrypter, pullDecrypter, KEY_SIZE, NONCE_SIZE } = require('../')

test('test basic encrypt and decrypt', async (t) => {
  // generate a random secret, `KEYBYTES` bytes long.
  const key = randomBytes(KEY_SIZE)
  // generate a random nonce, `NONCE_SIZE` bytes long.
  const nonce = randomBytes(NONCE_SIZE)

  const plaintext1 = Buffer.from('hello world')

  await new Promise((resolve, reject) => {
    pull(
      pull.values([plaintext1]),
      pullEncrypter(key, nonce),
      pull.through((ciphertext) => {
        console.log('Encrypted: ', ciphertext)
      }),
      pullDecrypter(key, nonce),
      pull.concat((err, plaintext2) => {
        if (err) return reject(err)
        assert.equal(plaintext2.toString('utf8'), plaintext1.toString('utf8'))
        resolve()
      }),
    )
  })
})
