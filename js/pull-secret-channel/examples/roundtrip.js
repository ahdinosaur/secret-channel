const { randomBytes } = require('crypto')
const pull = require('pull-stream')
const { pullEncrypter, pullDecrypter, KEY_SIZE, NONCE_SIZE } = require('../')

// generate a random secret, `KEY_SIZE` bytes long.
const key = randomBytes(KEY_SIZE)
// generate a random nonce, `NONCE_SIZE` bytes long.
const nonce = randomBytes(NONCE_SIZE)

const plaintext1 = Buffer.from('hello world')

pull(
  pull.values([plaintext1]),

  // encrypt every byte
  pullEncrypter(key, nonce),

  // the encrypted stream
  pull.through((ciphertext) => {
    console.log('Encrypted: ', ciphertext)
  }),

  // decrypt every byte
  pullDecrypter(key, nonce),

  pull.concat((err, plaintext2) => {
    if (err) throw err
    console.log('Decrypted: ', plaintext2)
  }),
)
