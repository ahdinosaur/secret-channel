module.exports = {
  incrementBuffer,
}

// https://github.com/dominictarr/pull-box-stream/issues/9#issuecomment-307557323
function incrementBuffer(buf) {
  for (let i = 0, len = buf.length, c = 1; i < len; i++) {
    buf[i] = c += buf[i]
    c >>= 8
  }
}
