const test = require('node:test')
const assert = require('node:assert')
const pull = require('pull-stream')
const { randomBytes } = require('crypto')
const { KEY_SIZE, pullEncrypter, pullDecrypter } = require('../')

test('test basic encrypt and decrypt', async (t) => {
  // generate a random secret, `KEYBYTES` bytes long.
  const key = randomBytes(KEY_SIZE)

  const plaintext1 = Buffer.from('hello world')

  await new Promise((resolve, reject) => {
    pull(
      pull.values([plaintext1]),
      pullEncrypter(key),
      pull.through((ciphertext) => {
        console.log('Encrypted: ', ciphertext)
      }),
      pullDecrypter(key),
      pull.concat((err, plaintext2) => {
        if (err) return reject(err)
        assert.equal(plaintext2.toString('utf8'), plaintext1.toString('utf8'))
        resolve()
      }),
    )
  })
})
