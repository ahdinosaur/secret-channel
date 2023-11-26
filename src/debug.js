const b4a = require('b4a')
const createDebug = require('debug')

createDebug.formatters.h = (v) => {
  return b4a.toString(v, 'hex')
}

const debug = createDebug('secret-channel')

module.exports = debug
