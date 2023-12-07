const test = require('node:test')
const assert = require('node:assert')
const pull = require('pull-stream')
const { randomBytes } = require('crypto')
const { pullEncrypter, pullDecrypter, KEY_SIZE, NONCE_SIZE } = require('../')
const { randomInt } = require('node:crypto')

test.skip('encrypt and decrypt: simple', async (t) => {
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

test('encrypt and decrypt: random buffers', async (t) => {
  // generate a random secret, `KEYBYTES` bytes long.
  const key = randomBytes(KEY_SIZE)
  // generate a random nonce, `NONCE_SIZE` bytes long.
  const nonce = randomBytes(NONCE_SIZE)

  const inputBuffers = randomBuffers(randomInt(1e2, 1e3), () => randomInt(1, 1e5))

  return new Promise((resolve, reject) => {
    pull(
      pull.values(inputBuffers),
      pullEncrypter(key, nonce),
      pullDecrypter(key, nonce),
      pull.collect((err, outputBuffers) => {
        if (err) return reject(err)

        const input = Buffer.concat(inputBuffers)
        const output = Buffer.concat(outputBuffers)
        assert.equal(output.length, input.length)
        assert.equal(output.toString('utf8'), input.toString('utf8'))
        resolve()
      }),
    )
  })
})

function randomBuffers(bufferCount, getBufferLength) {
  const buffers = []
  for (let i = 0; i < bufferCount; i++) {
    buffers.push(randomBytes(getBufferLength()))
  }
  return buffers
}
