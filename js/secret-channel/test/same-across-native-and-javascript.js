const b4a = require('b4a')
const test = require('node:test')
const assert = require('node:assert')
const { randomBytes, randomInt } = require('node:crypto')

const native = require('../src/index')
const js = require('../src/javascript')

test('encrypt: native and javascript are the same', async (t) => {
  // generate a random secret, `KEYBYTES` bytes long.
  const key = randomBytes(native.KEY_SIZE)

  const contents = []
  for (let i = 0; i < randomInt(100, 1000); i++) {
    contents.push(randomBytes(randomInt(10, 100)))
  }

  const nativeEncrypter = native.createEncrypter(key)
  const jsEncrypter = js.createEncrypter(key)

  for (let i = 0; i < contents.length; i++) {
    const content = contents[i]

    const nativeBytes = b4a.concat(nativeEncrypter.next(content))

    const jsContent = Uint8Array.from(content)
    const jsBytes = b4a.concat(jsEncrypter.next(jsContent))

    assert(b4a.equals(nativeBytes, jsBytes), `contents match at index ${i}`)
  }

  const nativeBytes = nativeEncrypter.end()
  const jsBytes = jsEncrypter.end()
  assert(b4a.equals(nativeBytes, jsBytes), 'end match')
})
