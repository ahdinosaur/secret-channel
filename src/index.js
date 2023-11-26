const protocol = require('./protocol')
const crypto = require('./crypto-native')
const constants = require('./constants')

module.exports = {
  ...protocol(crypto),
  ...constants,
}
