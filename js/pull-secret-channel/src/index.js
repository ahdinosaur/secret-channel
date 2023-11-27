const pullThrough = require('pull-through')
const pullReader = require('pull-reader')
const {
  createEncrypter,
  createDecrypter,
  KEY_SIZE,
  NONCE_SIZE,
  LENGTH_OR_END_CIPHERTEXT,
  TAG_SIZE,
} = require('secret-channel')

module.exports = {
  pullEncrypter,
  pullDecrypter,
  KEY_SIZE,
  NONCE_SIZE,
  TAG_SIZE,
}

function pullEncrypter(key, nonce) {
  const encrypter = createEncrypter(key, nonce)

  return pullThrough(
    function pullEncrypterData(contentPlaintext) {
      const [lengthCiphertext, contentCiphertext] = encrypter.next(contentPlaintext)
      this.queue(lengthCiphertext)
      this.queue(contentCiphertext)
    },

    function pullEncrypterEnd() {
      const endCiphertext = encrypter.end()
      this.queue(endCiphertext)
      this.queue(null)
    },
  )
}

function pullDecrypter(key, nonce) {
  const decrypter = createDecrypter(key, nonce)

  let ending = null
  const reader = pullReader()

  return function pullDecrypterThrough(read) {
    reader(read)

    return function pullDecrypterSource(end, cb) {
      if (end) return reader.abort(end, cb)
      if (ending) return cb(ending)

      reader.read(LENGTH_OR_END_CIPHERTEXT, function (err, lengthOrEndCiphertext) {
        if (err) {
          if (err === true) {
            ending = new Error(
              'pull-secret-channel/decrypter: stream ended before end-of-stream message',
            )
          } else {
            ending = err
          }
          return cb(ending)
        }

        let lengthOrEnd
        try {
          lengthOrEnd = decrypter.lengthOrEnd(lengthOrEndCiphertext)
        } catch (err) {
          ending = err
          // TODO attach error context
          return abort(err)
        }

        if (lengthOrEnd.type === 'end-of-stream') {
          ending = true
          return cb(ending)
        }

        const { length } = lengthOrEnd
        reader.read(length + TAG_SIZE, function (err, contentCiphertext) {
          if (err) {
            ending = err
            return cb(ending)
          }

          let contentPlaintext
          try {
            contentPlaintext = decrypter.content(contentCiphertext)
          } catch (err) {
            ending = err
            // TODO attach error context
            return abort(err)
          }

          cb(null, contentPlaintext)
        })
      })

      // use abort when the input was invalid,
      // but the source hasn't actually ended yet.
      function abort(err) {
        ending = err || true
        reader.abort(ending, cb)
      }
    }
  }
}
