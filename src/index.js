const protocol = require('./protocol')
const crypto = require('./crypto-native')
const constants = require('./constants')

module.exports = {
  createStreamEncrypter,
  ...constants,
}

function createStreamEncrypter(key) {
  return protocol.createStreamEncrypter(crypto, key)
}
