const protocol = require('./protocol')
const crypto = require('./crypto-javascript')
const constants = require('./constants')

module.exports = {
  createStreamEncrypter,
  ...constants,
}

function createStreamEncrypter(key) {
  return protocol.createStreamEncrypter(crypto, key)
}
