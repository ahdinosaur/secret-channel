// @ts-ignore
const pullThrough = require('pull-through')
// @ts-ignore
const pullReader = require('pull-reader')
const {
  createEncrypter,
  createDecrypter,
  KEY_SIZE,
  NONCE_SIZE,
  LENGTH_OR_END_CIPHERTEXT,
  TAG_SIZE,
  MAX_CONTENT_LENGTH,
} = require('secret-channel')

module.exports = {
  pullEncrypter,
  pullDecrypter,
  KEY_SIZE,
  NONCE_SIZE,
  TAG_SIZE,
}

/**
  @typedef {Buffer | Uint8Array} B4A
  @typedef {null | true | Error} End
  @typedef {(end: End, cb: (end: End, data?: any) => void) => void} Source
  @typedef {{
     queue: (buf: B4A | null) => void
     emit: (event: 'data' | 'end' | 'error', data?: any) => void
  }} PullThroughThis
*/

/**
 * @param {B4A} key
 * @param {B4A} nonce
 */
function pullEncrypter(key, nonce) {
  const encrypter = createEncrypter(key, nonce)

  return pullThrough(
    /**
     * @this {PullThroughThis}
     * @param {B4A} contentPlaintext
     */
    function pullEncrypterData(contentPlaintext) {
      if (contentPlaintext.length === 0) {
        return // skip
      }

      try {
        let totalContentPlaintext = contentPlaintext
        while (totalContentPlaintext.length > 0) {
          const nextContentPlaintext = totalContentPlaintext.subarray(0, MAX_CONTENT_LENGTH)
          totalContentPlaintext = totalContentPlaintext.subarray(MAX_CONTENT_LENGTH)

          const [lengthCiphertext, contentCiphertext] = encrypter.next(nextContentPlaintext)
          this.queue(lengthCiphertext)
          this.queue(contentCiphertext)
        }
      } catch (err) {
        this.emit('error', err)
      }
    },

    /**
     * @this {PullThroughThis}
     */
    function pullEncrypterEnd() {
      const endCiphertext = encrypter.end()
      this.queue(endCiphertext)
      this.queue(null)
    },
  )
}

/**
 * @param {B4A} key
 * @param {B4A} nonce
 */
function pullDecrypter(key, nonce) {
  const decrypter = createDecrypter(key, nonce)

  /** @type {End} */
  let ending = null
  const reader = pullReader()

  /**
   * @param {Source} read
   */
  return function pullDecrypterThrough(read) {
    reader(read)

    /**
     * @param {End} end
     * @param {(end: End, data?: B4A) => void} cb
     */
    return function pullDecrypterSource(end, cb) {
      if (end) return reader.abort(end, cb)
      if (ending) return cb(ending)

      reader.read(
        LENGTH_OR_END_CIPHERTEXT,

        /**
         * @param {End} err
         * @param {B4A} lengthOrEndCiphertext
         */
        function (err, lengthOrEndCiphertext) {
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
          } catch (/** @type any */ err) {
            ending = err
            // TODO attach error context
            return abort(err)
          }

          if (lengthOrEnd.type === 'end-of-stream') {
            ending = true
            return cb(ending)
          }

          const { length } = lengthOrEnd
          reader.read(
            length + TAG_SIZE,
            /**
             * @param {End} err
             * @param {B4A} contentCiphertext
             */
            function (err, contentCiphertext) {
              if (err) {
                ending = err
                return cb(ending)
              }

              let contentPlaintext
              try {
                contentPlaintext = decrypter.content(contentCiphertext)
              } catch (/** @type any */ err) {
                ending = err
                // TODO attach error context
                return abort(err)
              }

              cb(null, contentPlaintext)
            },
          )
        },
      )

      // use abort when the input was invalid,
      // but the source hasn't actually ended yet.
      /**
       * @param {End} err
       */
      function abort(err) {
        ending = err || true
        reader.abort(ending, cb)
      }
    }
  }
}
