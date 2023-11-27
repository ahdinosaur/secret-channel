const b4a = require('b4a')
const test = require('node:test')
const assert = require('node:assert')
const { randomBytes } = require('node:crypto')

const { increment } = require('../src/crypto-native')

// test that incrementing a nonce is the same as xor-ing a counter with the nonce

test('increment(nonce) is same as xor(increment(counter), nonce)', () => {
  const NONCE_SIZE = 4
  const MAX_COUNTER = 2 ** NONCE_SIZE

  const originalNonce = randomBytes(NONCE_SIZE)
  const incrementNonce = b4a.allocUnsafe(NONCE_SIZE)
  b4a.copy(originalNonce, incrementNonce)
  const counterNonce = b4a.allocUnsafe(NONCE_SIZE)
  const xorNonce = b4a.allocUnsafe(NONCE_SIZE)

  for (let counter = 0; counter < MAX_COUNTER; counter++, increment(incrementNonce)) {
    b4a.writeUInt32LE(counterNonce, counter, 0)
    xor(originalNonce, counterNonce, xorNonce)

    console.log('increment', incrementNonce)
    console.log('xor', xorNonce)

    assert(b4a.equals(incrementNonce, xorNonce))
  }
})

function xor(a, b, output) {
  if (a.length !== b.length) {
    throw new Error('xor: inputs should have the same length')
  }

  if (a.length !== output.length) {
    throw new Error('xor: output should have the same length as inputs')
  }

  for (let i = 0; i < a.length; i++) {
    output[i] = a[i] ^ b[i]
  }
}
