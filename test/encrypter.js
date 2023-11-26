const test = require('node:test')
const assert = require('node:assert')
const { randomBytes } = require('node:crypto')
const { TextEncoder } = require('node:util')

const { StreamEncrypter, KEY_SIZE } = require('../')

test('test hello world goodbye', async (t) => {
  const textEncoder = new TextEncoder()
  const content1 = textEncoder.encode('hello')
  const content2 = textEncoder.encode('world')

  // generate a random secret, `KEYBYTES` bytes long.
  const key = randomBytes(KEY_SIZE)

  const encrypter = new StreamEncrypter(key)

  console.log(encrypter.next(content1))
  console.log(encrypter.next(content2))
  console.log(encrypter.end())
})
