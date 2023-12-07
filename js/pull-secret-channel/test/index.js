const test = require('node:test')
const assert = require('node:assert')
const pull = require('pull-stream')
const pullBitflipper = require('pull-bitflipper')
const { randomBytes } = require('crypto')
const { pullEncrypter, pullDecrypter, KEY_SIZE, NONCE_SIZE } = require('../')
const { randomInt } = require('node:crypto')

test('encrypt and decrypt: simple', async (t) => {
  // generate a random secret, `KEYBYTES` bytes long.
  const key = randomBytes(KEY_SIZE)
  // generate a random nonce, `NONCE_SIZE` bytes long.
  const nonce = randomBytes(NONCE_SIZE)

  const plaintext1 = Buffer.from('hello world')

  await new Promise((resolve, _reject) => {
    pull(
      pull.values([plaintext1]),
      pullEncrypter(key, nonce),
      pullDecrypter(key, nonce),
      pull.concat((err, plaintext2) => {
        assert.ifError(err)
        assert.equal(plaintext2.toString('utf8'), plaintext1.toString('utf8'))
        resolve()
      }),
    )
  })
})

test('encrypt and decrypt: random buffers', async (t) => {
  const key = randomBytes(KEY_SIZE)
  const nonce = randomBytes(NONCE_SIZE)
  const inputBuffers = randomBuffers(randomInt(1e2, 1e3), () => randomInt(1, 1e5))

  await new Promise((resolve, _reject) => {
    pull(
      pull.values(inputBuffers),
      pullEncrypter(key, nonce),
      pullDecrypter(key, nonce),
      pull.collect((err, outputBuffers) => {
        assert.ifError(err)

        const input = Buffer.concat(inputBuffers)
        const output = Buffer.concat(outputBuffers)
        assert.equal(output.length, input.length)
        assert.equal(output.toString('utf8'), input.toString('utf8'))

        resolve()
      }),
    )
  })
})

test('detect flipped bits', async (t) => {
  const key = randomBytes(KEY_SIZE)
  const nonce = randomBytes(NONCE_SIZE)
  const inputBuffers = randomBuffers(100, () => 1024)

  await new Promise((resolve, _reject) => {
    pull(
      pull.values(inputBuffers),
      pullEncrypter(key, nonce),
      pullBitflipper(0.2),
      pullDecrypter(key, nonce),
      pull.collect((err, outputBuffers) => {
        assert.ok(err)
        assert.equal(err.message, 'could not verify data')
        assert.notEqual(outputBuffers.length, inputBuffers.length)
        resolve()
      }),
    )
  })
})

test('protect against reordering', async (t) => {
  const key = randomBytes(KEY_SIZE)
  const nonce = randomBytes(NONCE_SIZE)
  const inputBuffers = randomBuffers(100, () => 1024)

  await new Promise((resolve, _reject) => {
    pull(
      pull.values(inputBuffers),
      pullEncrypter(key, nonce),
      pull.collect((err, valid) => {
        assert.ifError(err)

        // randomly switch two blocks
        const invalid = valid.slice()
        // since every even packet is a header,
        // moving those will produce valid messages
        // but the counters will be wrong.
        const i = randomInt(valid.length)
        let j
        do j = randomInt(valid.length)
        while (j === i)
        invalid[i] = valid[j]
        invalid[i + 1] = valid[j + 1]
        invalid[j] = valid[i]
        invalid[j + 1] = valid[i + 1]

        pull(
          pull.values(invalid),
          pullDecrypter(key, nonce),
          pull.collect((err, outputBuffers) => {
            assert.ok(err)
            assert.equal(err.message, 'could not verify data')
            assert.notEqual(outputBuffers.length, inputBuffers.length)
            resolve()
          }),
        )
      }),
    )
  })
})

test('detect unexpected hangup', async (t) => {
  const key = randomBytes(KEY_SIZE)
  const nonce = randomBytes(NONCE_SIZE)

  const inputBuffers = [
    Buffer.from('I <3 TLS\n'),
    Buffer.from('...\n'),
    Buffer.from('NOT!!!!!!!!!!!!!!!\n'),
  ]

  await new Promise((resolve, _reject) => {
    pull(
      pull.values(inputBuffers),
      pullEncrypter(key, nonce),
      pull.take(4), // header content header content.
      pullDecrypter(key, nonce),
      pull.collect((err, outputBuffers) => {
        assert.ok(err) // expects an error
        assert.equal(
          err.message,
          'pull-secret-channel/decrypter: stream ended before end-of-stream message',
        )
        assert.equal(outputBuffers.length, 2)
        assert.equal(Buffer.concat(outputBuffers).toString('utf8'), 'I <3 TLS\n...\n')
        resolve()
      }),
    )
  })
})

test('immediately hangup', async (t) => {
  const key = randomBytes(KEY_SIZE)
  const nonce = randomBytes(NONCE_SIZE)

  await new Promise((resolve, _reject) => {
    pull(
      pull.values([]),
      pullEncrypter(key, nonce),
      pullDecrypter(key, nonce),
      pull.collect((err, outputBuffers) => {
        assert.ifError(err)
        assert.deepEqual(outputBuffers, [])
        resolve()
      }),
    )
  })
})

test('skip empty buffers', async (t) => {
  const key = randomBytes(KEY_SIZE)
  const nonce = randomBytes(NONCE_SIZE)

  const inputBuffers = [
    Buffer.alloc(0),
    Buffer.from('hello'),
    Buffer.alloc(0),
    Buffer.from('world'),
  ]
  let chunks = 0

  await new Promise((resolve, _reject) => {
    pull(
      pull.values(inputBuffers),
      pullEncrypter(key, nonce),
      pull.through(() => {
        chunks++
      }),
      pullDecrypter(key, nonce),
      pull.collect((err, outputBuffers) => {
        assert.ifError(err)

        const input = Buffer.concat(inputBuffers)
        const output = Buffer.concat(outputBuffers)
        assert.equal(output.length, input.length)
        assert.equal(output.toString('utf8'), input.toString('utf8'))

        assert.equal(chunks, 5) // header, content, header, content, end-of-stream

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
