const { chacha20poly1305 } = require('@noble/ciphers/chacha')

module.exports = {
  createCipher,
  pad,
  unpad,
}

function createCipher(key, nonce) {
  return chacha20poly1305(key, nonce)
}

function pad(block, dataSize) {
  if (dataSize >= block.byteLength) {
    throw new Error('secret-channel/crypto/pad: dataSize is bigger or equal to block size')
  }
  block[dataSize] = 0x80
  block.fill(0, dataSize + 1)
}

function unpad(block) {
  for (let i = block.byteLength - 1; i >= 0; i--) {
    switch (block[i]) {
      case 0x80:
        return block.slice(0, i)
      case 0x00:
        break
      default:
        throw new Error(
          `secret-channel/crypto/unpad: found wrong byte 0x${block[i].toString(
            16,
          )}, expecting 0x80 or 0x00`,
        )
    }
  }
}
