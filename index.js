const _sodium = require('libsodium-wrappers')
const stringify = require('json-stable-stringify')

let sodium
let HASH_KEY

function _throwUninitErr() {
  throw new Error('Initialize function must be called before using other functions from this library.')
}

// Returns 32-bytes random hex string, otherwise the number of bytes can be specified as an integer
function randomBytes(bytes = 32) {
  if (!sodium) _throwUninitErr()
  if (!Number.isInteger(bytes) || bytes <= 0) {
    throw new TypeError('Bytes must be given as integer greater than zero.')
  }
  return sodium.to_hex(sodium.randombytes_buf(bytes))
}

// Returns the Blake2b hash of the input string or Buffer, default output type is hex
function hash(input, fmt = 'hex') {
  if (!sodium) _throwUninitErr()
  if (!HASH_KEY) {
    throw new Error('Hash key must be passed to the initialize function before .')
  }
  if (typeof input !== 'string') {
    throw new TypeError('Input must be a string or buffer.')
  }
  let buf = sodium.from_string(input)
  let hashed = sodium.crypto_generichash(32, buf, HASH_KEY)
  let output
  switch (fmt) {
    case 'uint8arr':
      output = hashed
      break
    case 'hex':
      output = sodium.to_hex(hashed)
      break
    default:
      throw Error('Invalid type for output format.')
  }
  return output
}

// Returns the hash of the provided object as a hex string, takes an optional second parameter to hash an object with the "sign" field
function hashObj(obj, removeSign = false) {
  if (typeof obj !== 'object') {
    throw TypeError('Input must be an object.')
  }
  function performHash(obj) {
    let input = stringify(obj)
    let hashed = hash(input)
    return hashed
  }
  if (removeSign) {
    if (!obj.sign) {
      throw Error('Object must contain a sign field if removeSign is flagged true.')
    }
    let signObj = obj.sign
    delete obj.sign
    let hashed = performHash(obj)
    obj.sign = signObj
    return hashed
  } else {
    return performHash(obj)
  }
}

function encryptAB(input, pub, sec) {
  let inputBuf, pubBuf, secBuf, pubBoxBuf, secBoxBuf, nonce, encrypted
  if (!sodium) _throwUninitErr()
  if (typeof input !== 'string') {
    throw new TypeError('Message to encrypt must be a string.')
  }
  try {
    pubBuf = sodium.from_hex(pub)
  } catch (e) {
    throw new TypeError('Secret key string must be in hex format')
  }
  try {
    secBuf = sodium.from_hex(sec)
  } catch (e) {
    throw new TypeError('Secret key string must be in hex format')
  }
  inputBuf = sodium.from_string(input)
  // we need to convert signing keys to boxing keys
  pubBoxBuf = sodium.crypto_sign_ed25519_pk_to_curve25519(pubBuf)
  secBoxBuf = sodium.crypto_sign_ed25519_sk_to_curve25519(secBuf)
  // a random number that must be passed on to the recipient along with the message
  nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES)
  try {
    encrypted = sodium.crypto_box_easy(inputBuf, nonce, pubBoxBuf, secBoxBuf)
  } catch (e) {
    throw new TypeError('Could not encrypt the message')
  }

  return sodium.to_hex(nonce) + ':' + sodium.to_base64(encrypted)
}

function decryptAB(input, pub, sec) {
  let inputBuf, pubBuf, secBuf, pubBoxBuf, secBoxBuf, nonce, decrypted
  let nonceHex, inputBase64

  if (!sodium) _throwUninitErr()
  if (typeof input !== 'string') {
    throw new TypeError('Message to decrypt must be a string.')
  }
  try {
    ;[nonceHex, inputBase64] = input.split(':')
    nonce = sodium.from_hex(nonceHex)
    inputBuf = sodium.from_base64(inputBase64)
  } catch (e) {
    throw new TypeError('Message to decrypt in must have nonce:ciphertext as hex:base64')
  }
  try {
    pubBuf = sodium.from_hex(pub)
  } catch (e) {
    throw new TypeError('Secret key string must be in hex format')
  }
  try {
    secBuf = sodium.from_hex(sec)
  } catch (e) {
    throw new TypeError('Secret key string must be in hex format')
  }
  // we need to convert signing keys to boxing keys
  pubBoxBuf = sodium.crypto_sign_ed25519_pk_to_curve25519(pubBuf)
  secBoxBuf = sodium.crypto_sign_ed25519_sk_to_curve25519(secBuf)
  try {
    decrypted = sodium.crypto_box_open_easy(inputBuf, nonce, pubBoxBuf, secBoxBuf)
  } catch (e) {
    throw new TypeError('Could not decrypt the message')
  }

  return sodium.to_string(decrypted)
}

// Generates and retuns {publicKey, secretKey} as hex strings
function generateKeypair() {
  let publicBox, privateBox
  if (!sodium) _throwUninitErr()
  let { publicKey, privateKey } = sodium.crypto_sign_keypair()
  publicBox = sodium.crypto_sign_ed25519_pk_to_curve25519(publicKey)
  // console.log('publicBox', publicBox)
  return {
    publicKey: sodium.to_hex(publicKey),
    secretKey: sodium.to_hex(privateKey),
  }
}

// Returns a signature obtained by signing the input hash (hex string or buffer) with the sk string
function sign(input, sk) {
  if (!sodium) _throwUninitErr()
  let inputBuf
  let skBuf
  try {
    inputBuf = sodium.from_hex(input)
  } catch (e) {
    throw new TypeError('Input string must be in hex format.')
  }
  try {
    skBuf = sodium.from_hex(sk)
  } catch (e) {
    throw new TypeError('Secret key string must be in hex format')
  }
  let sig
  try {
    sig = sodium.crypto_sign(inputBuf, skBuf)
  } catch (e) {
    throw new Error('Failed to sign input with provided secret key.')
  }
  return sodium.to_hex(sig)
}

/*
  Attaches a sign field to the input object, containing a signed version
  of the hash of the object, along with the public key of the signer
*/
function signObj(obj, sk, pk) {
  if (typeof obj !== 'object') {
    throw new TypeError('Input must be an object.')
  }
  if (typeof sk !== 'string') {
    throw new TypeError('Secret key must be a string.')
  }
  if (typeof pk !== 'string') {
    throw new TypeError('Public key must be a string.')
  }
  let objStr = stringify(obj)
  let hashed = hash(objStr)
  let sig = sign(hashed, sk)
  obj.sign = { owner: pk, sig }
}

// Returns true if the hash of the input was signed by the owner of the pk
function verify(msg, sig, pk) {
  if (!sodium) _throwUninitErr()
  if (typeof msg !== 'string') {
    throw new TypeError('Message to compare must be a string.')
  }
  let sigBuf
  if (typeof sig !== 'string') {
    throw new TypeError('Signature must be a hex string.')
  } else {
    try {
      sigBuf = sodium.from_hex(sig)
    } catch (e) {
      throw new TypeError('Signature must be a hex string.')
    }
  }
  if (typeof pk !== 'string') {
    throw new TypeError('Public key must be a hex string.')
  }
  let pkBuf
  try {
    pkBuf = sodium.from_hex(pk)
  } catch (e) {
    throw new TypeError('Public key must be a hex string.')
  }
  try {
    let verified = sodium.to_hex(sodium.crypto_sign_open(sigBuf, pkBuf))
    return verified === msg
  } catch (e) {
    throw new Error('Unable to verify provided signature with provided public key.')
  }
}

// Returns true if the hash of the object minus the sign field matches the signed message in the sign field
function verifyObj(obj) {
  if (typeof obj !== 'object') {
    throw new TypeError('Input must be an object.')
  }
  if (!obj.sign || !obj.sign.owner || !obj.sign.sig) {
    throw new Error('Object must contain a sign field with the following data: { owner, sig }')
  }
  if (typeof obj.sign.owner !== 'string') {
    throw new TypeError('Owner must be a public key represented as a hex string.')
  }
  if (typeof obj.sign.sig !== 'string') {
    throw new TypeError('Signature must be a valid signature represented as a hex string.')
  }
  let objHash = hashObj(obj, true)
  return verify(objHash, obj.sign.sig, obj.sign.owner)
}

async function initialize(key) {
  await _sodium.ready
  sodium = _sodium
  console.log(sodium)
  if (!key) {
    throw new Error('Hash key must be passed to initialize function.')
  }
  try {
    HASH_KEY = sodium.from_hex(key)
    if (HASH_KEY.length !== 32) {
      throw new TypeError()
    }
  } catch (e) {
    throw new TypeError('Hash key must be a 32-byte string.')
  }
}

exports.initialize = initialize
exports.stringify = stringify
exports.randomBytes = randomBytes
exports.hash = hash
exports.hashObj = hashObj
exports.generateKeypair = generateKeypair
exports.sign = sign
exports.signObj = signObj
exports.verify = verify
exports.verifyObj = verifyObj
exports.encryptAB = encryptAB
exports.decryptAB = decryptAB
