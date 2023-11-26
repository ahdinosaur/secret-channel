const b4a = require('b4a')
const test = require('node:test')
const assert = require('node:assert')
const { randomBytes } = require('node:crypto')

const { createStreamEncrypter, KEY_SIZE } = require('../')

test('test hello world', async (t) => {
  // generate a random secret, `KEYBYTES` bytes long.
  const key = randomBytes(KEY_SIZE)

  const content1 = b4a.from('hello')
  const content2 = b4a.from('world')

  const encrypter = createStreamEncrypter(key)

  console.log('native')
  console.log(encrypter.next(content1))
  console.log(encrypter.next(content2))
  console.log(encrypter.end())
})
