const KEY_SIZE = 32
const NONCE_SIZE = 12
const TAG_SIZE = 16

const LENGTH_OR_END_PLAINTEXT = 2
const LENGTH_OR_END_CIPHERTEXT = LENGTH_OR_END_PLAINTEXT + TAG_SIZE

const MAX_CONTENT_LENGTH = 2 ** 16 - 1

module.exports = {
  KEY_SIZE,
  NONCE_SIZE,
  TAG_SIZE,
  LENGTH_OR_END_PLAINTEXT,
  LENGTH_OR_END_CIPHERTEXT,
  MAX_CONTENT_LENGTH,
}
