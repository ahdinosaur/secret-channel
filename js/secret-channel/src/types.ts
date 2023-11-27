export type B4A = Buffer | Uint8Array

export type Encrypt = (key: B4A, nonce: B4A, plaintext: B4A) => B4A
export type Decrypt = (key: B4A, nonce: B4A, ciphertext: B4A) => B4A
export type Increment = (buf: B4A) => void
export type IsZero = (buf: B4A) => boolean

export type Crypt = {
  encrypt: Encrypt
  decrypt: Decrypt
  increment: Increment
  isZero: IsZero
}
