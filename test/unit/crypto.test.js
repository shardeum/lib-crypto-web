const crypto = require('../../index.js')

// Test hash key for initialization
const TEST_HASH_KEY = '64f152869ca2d473e4ba64ab53f49ccdb2edae22da192c126850970e788af347'

// Mock console.log to prevent output during tests
beforeAll(() => {
  jest.spyOn(console, 'log').mockImplementation(() => {})
  jest.spyOn(console, 'warn').mockImplementation(() => {})
  jest.spyOn(console, 'error').mockImplementation(() => {})
})

afterAll(() => {
  jest.restoreAllMocks()
})

describe('Crypto Library', () => {
  const testHashKey = '69fa4195670576c0160d660c3be36556ff8d504725be8a59b5a96509e0c994bc'

  // Skip uninitialized tests since the module state is shared

  // Initialize the library before all tests
  beforeAll(async () => {
    await crypto.initialize(testHashKey)
  })

  describe('initialization', () => {
    it('should initialize successfully with a valid hash key', async () => {
      await expect(crypto.initialize(testHashKey)).resolves.not.toThrow()
    })

    it('should throw an error if hash key is invalid', async () => {
      await expect(crypto.initialize('invalid')).rejects.toThrow()
    })

    it('should throw error when initializing without key', async () => {
      await expect(crypto.initialize()).rejects.toThrow('Hash key must be passed to initialize function')
      await expect(crypto.initialize(null)).rejects.toThrow('Hash key must be passed to initialize function')
      await expect(crypto.initialize('')).rejects.toThrow('Hash key must be passed to initialize function')
    })

    it('should throw error when initializing with non-hex key', async () => {
      await expect(crypto.initialize('not-hex')).rejects.toThrow('Hash key must be a 32-byte string')
      await expect(crypto.initialize('zzz')).rejects.toThrow('Hash key must be a 32-byte string')
      await expect(crypto.initialize('12345g')).rejects.toThrow('Hash key must be a 32-byte string')
    })

    it('should throw error when initializing with wrong length key', async () => {
      // Too short (31 bytes = 62 hex chars)
      await expect(crypto.initialize('a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1')).rejects.toThrow('Hash key must be a 32-byte string')
      // Too long (33 bytes = 66 hex chars)
      await expect(crypto.initialize('a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3')).rejects.toThrow('Hash key must be a 32-byte string')
    })
  })

  describe('stringify export', () => {
    it('should export the stringify function', () => {
      expect(crypto.stringify).toBeDefined()
      expect(typeof crypto.stringify).toBe('function')
    })

    it('should stringify objects deterministically', () => {
      const obj1 = { b: 2, a: 1, c: 3 }
      const obj2 = { a: 1, b: 2, c: 3 }
      const obj3 = { c: 3, b: 2, a: 1 }
      
      const str1 = crypto.stringify(obj1)
      const str2 = crypto.stringify(obj2)
      const str3 = crypto.stringify(obj3)
      
      expect(str1).toBe(str2)
      expect(str2).toBe(str3)
      expect(str1).toBe('{"a":1,"b":2,"c":3}')
    })
  })

  describe('randomBytes', () => {
    it('should generate random bytes of default length (32)', () => {
      const bytes = crypto.randomBytes()
      expect(bytes).toHaveLength(64) // 32 bytes in hex is 64 characters
    })

    it('should generate random bytes of specified length', () => {
      const bytes = crypto.randomBytes(16)
      expect(bytes).toHaveLength(32) // 16 bytes in hex is 32 characters
    })

    it('should throw an error if bytes parameter is invalid', () => {
      expect(() => crypto.randomBytes('invalid')).toThrow()
    })
  })

  describe('hash', () => {
    it('should hash a string input and return a hex string by default', () => {
      const hash = crypto.hash('test')
      expect(typeof hash).toBe('string')
      expect(hash).toMatch(/^[0-9a-f]{64}$/) // 32 bytes in hex is 64 characters
    })

    it('should return consistent hash for the same input', () => {
      const hash1 = crypto.hash('test')
      const hash2 = crypto.hash('test')
      expect(hash1).toBe(hash2)
    })

    it('should return different hashes for different inputs', () => {
      const hash1 = crypto.hash('test1')
      const hash2 = crypto.hash('test2')
      expect(hash1).not.toBe(hash2)
    })

    it('should support uint8arr output format', () => {
      const hash = crypto.hash('test', 'uint8arr')
      expect(hash).toBeInstanceOf(Uint8Array)
      expect(hash.length).toBe(32) // 32 bytes
    })

    it('should throw an error for invalid input type', () => {
      expect(() => crypto.hash(null)).toThrow()
    })

    it('should throw an error for invalid output format', () => {
      expect(() => crypto.hash('test', 'invalid')).toThrow()
    })
  })

  describe('hashObj', () => {
    it('should hash an object and return a hex string', () => {
      const obj = { test: 'value' }
      const hash = crypto.hashObj(obj)
      expect(typeof hash).toBe('string')
      expect(hash).toMatch(/^[0-9a-f]{64}$/)
    })

    it('should return consistent hash for the same object', () => {
      const obj = { test: 'value' }
      const hash1 = crypto.hashObj(obj)
      const hash2 = crypto.hashObj(obj)
      expect(hash1).toBe(hash2)
    })

    it('should hash objects with properties in different order the same way', () => {
      const obj1 = { a: 1, b: 2 }
      const obj2 = { b: 2, a: 1 }
      const hash1 = crypto.hashObj(obj1)
      const hash2 = crypto.hashObj(obj2)
      expect(hash1).toBe(hash2)
    })

    it('should hash an object without the sign field when removeSign is true', () => {
      const obj = { test: 'value', sign: { owner: 'test', sig: 'test' } }
      const hashWithSign = crypto.hashObj(obj, false)
      const hashWithoutSign = crypto.hashObj(obj, true)
      expect(hashWithSign).not.toBe(hashWithoutSign)
    })

    it('should throw an error for invalid input type', () => {
      expect(() => crypto.hashObj('not an object')).toThrow()
    })

    it('should throw an error when removeSign is true but object has no sign field', () => {
      const obj = { test: 'value' }
      expect(() => crypto.hashObj(obj, true)).toThrow()
    })
  })

  describe('generateKeypair', () => {
    it('should generate a keypair with publicKey and secretKey', () => {
      const keypair = crypto.generateKeypair()
      expect(keypair).toHaveProperty('publicKey')
      expect(keypair).toHaveProperty('secretKey')
      expect(keypair.publicKey).toMatch(/^[0-9a-f]{64}$/)
      expect(keypair.secretKey).toMatch(/^[0-9a-f]{128}$/)
    })
  })

  describe('sign and verify', () => {
    it('should sign a message hash and verify it successfully', () => {
      const keypair = crypto.generateKeypair()
      const message = 'test message'
      const messageHash = crypto.hash(message)

      const signature = crypto.sign(messageHash, keypair.secretKey)
      // The signature length can vary, but it should be a hex string
      expect(typeof signature).toBe('string')
      expect(signature).toMatch(/^[0-9a-f]+$/)

      const verified = crypto.verify(messageHash, signature, keypair.publicKey)
      expect(verified).toBe(true)
    })

    it('should fail verification with incorrect message', () => {
      const keypair = crypto.generateKeypair()
      const message1 = 'test message'
      const message2 = 'different message'
      const messageHash1 = crypto.hash(message1)
      const messageHash2 = crypto.hash(message2)

      const signature = crypto.sign(messageHash1, keypair.secretKey)

      // The verify function returns false for incorrect messages
      const verified = crypto.verify(messageHash2, signature, keypair.publicKey)
      expect(verified).toBe(false)
    })

    it('should fail verification with incorrect public key', () => {
      const keypair1 = crypto.generateKeypair()
      const keypair2 = crypto.generateKeypair()
      const message = 'test message'
      const messageHash = crypto.hash(message)

      const signature = crypto.sign(messageHash, keypair1.secretKey)

      // The verify function throws an error when verification fails with wrong public key
      expect(() => {
        crypto.verify(messageHash, signature, keypair2.publicKey)
      }).toThrow('Unable to verify provided signature with provided public key')
    })

    it('should throw error when signing with non-hex input', () => {
      const keypair = crypto.generateKeypair()
      
      expect(() => crypto.sign('not-hex', keypair.secretKey)).toThrow('Input string must be in hex format')
      expect(() => crypto.sign('zzz', keypair.secretKey)).toThrow('Input string must be in hex format')
      expect(() => crypto.sign('12345g', keypair.secretKey)).toThrow('Input string must be in hex format')
    })

    it('should throw error when signing with non-hex secret key', () => {
      const messageHash = crypto.hash('test')
      
      expect(() => crypto.sign(messageHash, 'not-hex')).toThrow('Secret key string must be in hex format')
      expect(() => crypto.sign(messageHash, 'zzz')).toThrow('Secret key string must be in hex format')
      expect(() => crypto.sign(messageHash, '12345g')).toThrow('Secret key string must be in hex format')
    })

    it('should throw error when verifying with non-string message', () => {
      const keypair = crypto.generateKeypair()
      const signature = crypto.sign(crypto.hash('test'), keypair.secretKey)
      
      expect(() => crypto.verify(123, signature, keypair.publicKey)).toThrow('Message to compare must be a string')
      expect(() => crypto.verify(null, signature, keypair.publicKey)).toThrow('Message to compare must be a string')
      expect(() => crypto.verify(undefined, signature, keypair.publicKey)).toThrow('Message to compare must be a string')
      expect(() => crypto.verify({}, signature, keypair.publicKey)).toThrow('Message to compare must be a string')
    })

    it('should throw error when verifying with non-string signature', () => {
      const keypair = crypto.generateKeypair()
      const messageHash = crypto.hash('test')
      
      expect(() => crypto.verify(messageHash, 123, keypair.publicKey)).toThrow('Signature must be a hex string')
      expect(() => crypto.verify(messageHash, null, keypair.publicKey)).toThrow('Signature must be a hex string')
      expect(() => crypto.verify(messageHash, undefined, keypair.publicKey)).toThrow('Signature must be a hex string')
      expect(() => crypto.verify(messageHash, {}, keypair.publicKey)).toThrow('Signature must be a hex string')
    })

    it('should throw error when verifying with non-hex signature', () => {
      const keypair = crypto.generateKeypair()
      const messageHash = crypto.hash('test')
      
      expect(() => crypto.verify(messageHash, 'not-hex', keypair.publicKey)).toThrow('Signature must be a hex string')
      expect(() => crypto.verify(messageHash, 'zzz', keypair.publicKey)).toThrow('Signature must be a hex string')
      expect(() => crypto.verify(messageHash, '12345g', keypair.publicKey)).toThrow('Signature must be a hex string')
    })

    it('should throw error when verifying with non-string public key', () => {
      const keypair = crypto.generateKeypair()
      const messageHash = crypto.hash('test')
      const signature = crypto.sign(messageHash, keypair.secretKey)
      
      expect(() => crypto.verify(messageHash, signature, 123)).toThrow('Public key must be a hex string')
      expect(() => crypto.verify(messageHash, signature, null)).toThrow('Public key must be a hex string')
      expect(() => crypto.verify(messageHash, signature, undefined)).toThrow('Public key must be a hex string')
      expect(() => crypto.verify(messageHash, signature, {})).toThrow('Public key must be a hex string')
    })

    it('should throw error when verifying with non-hex public key', () => {
      const keypair = crypto.generateKeypair()
      const messageHash = crypto.hash('test')
      const signature = crypto.sign(messageHash, keypair.secretKey)
      
      expect(() => crypto.verify(messageHash, signature, 'not-hex')).toThrow('Public key must be a hex string')
      expect(() => crypto.verify(messageHash, signature, 'zzz')).toThrow('Public key must be a hex string')
      expect(() => crypto.verify(messageHash, signature, '12345g')).toThrow('Public key must be a hex string')
    })
  })

  describe('signObj and verifyObj', () => {
    it('should sign an object and verify it successfully', () => {
      const keypair = crypto.generateKeypair()
      const obj = { test: 'value' }

      crypto.signObj(obj, keypair.secretKey, keypair.publicKey)

      expect(obj).toHaveProperty('sign')
      expect(obj.sign).toHaveProperty('owner')
      expect(obj.sign).toHaveProperty('sig')
      expect(obj.sign.owner).toBe(keypair.publicKey)

      const verified = crypto.verifyObj(obj)
      expect(verified).toBe(true)
    })

    it('should fail verification if object is modified after signing', () => {
      const keypair = crypto.generateKeypair()
      const obj = { test: 'value' }

      crypto.signObj(obj, keypair.secretKey, keypair.publicKey)
      obj.test = 'modified'

      // verifyObj returns false when verification fails, not throws
      const verified = crypto.verifyObj(obj)
      expect(verified).toBe(false)
    })

    it('should throw error when signing non-object', () => {
      const keypair = crypto.generateKeypair()
      
      expect(() => crypto.signObj('not-object', keypair.secretKey, keypair.publicKey)).toThrow('Input must be an object')
      expect(() => crypto.signObj(123, keypair.secretKey, keypair.publicKey)).toThrow('Input must be an object')
      // null will throw a different error due to trying to set property on null
      expect(() => crypto.signObj(null, keypair.secretKey, keypair.publicKey)).toThrow()
      expect(() => crypto.signObj(undefined, keypair.secretKey, keypair.publicKey)).toThrow('Input must be an object')
    })

    it('should throw error when signing with non-string secret key', () => {
      const keypair = crypto.generateKeypair()
      const obj = { test: 'value' }
      
      expect(() => crypto.signObj(obj, 123, keypair.publicKey)).toThrow('Secret key must be a string')
      expect(() => crypto.signObj(obj, null, keypair.publicKey)).toThrow('Secret key must be a string')
      expect(() => crypto.signObj(obj, undefined, keypair.publicKey)).toThrow('Secret key must be a string')
      expect(() => crypto.signObj(obj, {}, keypair.publicKey)).toThrow('Secret key must be a string')
    })

    it('should throw error when signing with non-string public key', () => {
      const keypair = crypto.generateKeypair()
      const obj = { test: 'value' }
      
      expect(() => crypto.signObj(obj, keypair.secretKey, 123)).toThrow('Public key must be a string')
      expect(() => crypto.signObj(obj, keypair.secretKey, null)).toThrow('Public key must be a string')
      expect(() => crypto.signObj(obj, keypair.secretKey, undefined)).toThrow('Public key must be a string')
      expect(() => crypto.signObj(obj, keypair.secretKey, {})).toThrow('Public key must be a string')
    })

    it('should throw error when verifying non-object', () => {
      expect(() => crypto.verifyObj('not-object')).toThrow('Input must be an object')
      expect(() => crypto.verifyObj(123)).toThrow('Input must be an object')
      // null will throw a different error due to trying to read property of null
      expect(() => crypto.verifyObj(null)).toThrow()
      expect(() => crypto.verifyObj(undefined)).toThrow('Input must be an object')
    })

    it('should throw error when verifying object without sign field', () => {
      const obj = { test: 'value' }
      expect(() => crypto.verifyObj(obj)).toThrow('Object must contain a sign field with the following data: { owner, sig }')
    })

    it('should throw error when verifying object without sign.owner', () => {
      const obj = { test: 'value', sign: { sig: 'somesig' } }
      expect(() => crypto.verifyObj(obj)).toThrow('Object must contain a sign field with the following data: { owner, sig }')
    })

    it('should throw error when verifying object without sign.sig', () => {
      const obj = { test: 'value', sign: { owner: 'someowner' } }
      expect(() => crypto.verifyObj(obj)).toThrow('Object must contain a sign field with the following data: { owner, sig }')
    })

    it('should throw error when verifying object with non-string sign.owner', () => {
      const obj = { test: 'value', sign: { owner: 123, sig: 'somesig' } }
      expect(() => crypto.verifyObj(obj)).toThrow('Owner must be a public key represented as a hex string')
    })

    it('should throw error when verifying object with non-string sign.sig', () => {
      const obj = { test: 'value', sign: { owner: 'someowner', sig: 123 } }
      expect(() => crypto.verifyObj(obj)).toThrow('Signature must be a valid signature represented as a hex string')
    })
  })

  describe('encryptAB and decryptAB', () => {
    it('should successfully encrypt and decrypt a message', () => {
      const keypairA = crypto.generateKeypair()
      const keypairB = crypto.generateKeypair()
      const message = 'test message'

      // A encrypts a message for B using B's public key and A's secret key
      const encrypted = crypto.encryptAB(message, keypairB.publicKey, keypairA.secretKey)
      expect(typeof encrypted).toBe('string')
      expect(encrypted).toContain(':') // Should contain nonce:ciphertext

      // B decrypts the message using A's public key and B's secret key
      const decrypted = crypto.decryptAB(encrypted, keypairA.publicKey, keypairB.secretKey)
      expect(decrypted).toBe(message)
    })

    it('should encrypt and decrypt an empty string', () => {
      const keypairA = crypto.generateKeypair()
      const keypairB = crypto.generateKeypair()
      const message = ''

      const encrypted = crypto.encryptAB(message, keypairB.publicKey, keypairA.secretKey)
      const decrypted = crypto.decryptAB(encrypted, keypairA.publicKey, keypairB.secretKey)
      expect(decrypted).toBe(message)
    })

    it('should produce different ciphertexts for the same message due to random nonce', () => {
      const keypairA = crypto.generateKeypair()
      const keypairB = crypto.generateKeypair()
      const message = 'test message'

      const encrypted1 = crypto.encryptAB(message, keypairB.publicKey, keypairA.secretKey)
      const encrypted2 = crypto.encryptAB(message, keypairB.publicKey, keypairA.secretKey)
      
      expect(encrypted1).not.toBe(encrypted2) // Different due to random nonce
      
      // Both should decrypt to the same message
      const decrypted1 = crypto.decryptAB(encrypted1, keypairA.publicKey, keypairB.secretKey)
      const decrypted2 = crypto.decryptAB(encrypted2, keypairA.publicKey, keypairB.secretKey)
      expect(decrypted1).toBe(message)
      expect(decrypted2).toBe(message)
    })

    it('should throw error when encrypting with invalid message type', () => {
      const keypairA = crypto.generateKeypair()
      const keypairB = crypto.generateKeypair()

      expect(() => crypto.encryptAB(123, keypairB.publicKey, keypairA.secretKey)).toThrow('Message to encrypt must be a string')
      expect(() => crypto.encryptAB(null, keypairB.publicKey, keypairA.secretKey)).toThrow('Message to encrypt must be a string')
      expect(() => crypto.encryptAB(undefined, keypairB.publicKey, keypairA.secretKey)).toThrow('Message to encrypt must be a string')
      expect(() => crypto.encryptAB({}, keypairB.publicKey, keypairA.secretKey)).toThrow('Message to encrypt must be a string')
    })

    it('should throw error when encrypting with invalid public key format', () => {
      const keypairA = crypto.generateKeypair()
      const message = 'test'

      expect(() => crypto.encryptAB(message, 'invalid', keypairA.secretKey)).toThrow('Secret key string must be in hex format')
      expect(() => crypto.encryptAB(message, '12345', keypairA.secretKey)).toThrow('Secret key string must be in hex format')
      expect(() => crypto.encryptAB(message, 'zzz', keypairA.secretKey)).toThrow('Secret key string must be in hex format')
    })

    it('should throw error when encrypting with invalid secret key format', () => {
      const keypairB = crypto.generateKeypair()
      const message = 'test'

      expect(() => crypto.encryptAB(message, keypairB.publicKey, 'invalid')).toThrow('Secret key string must be in hex format')
      expect(() => crypto.encryptAB(message, keypairB.publicKey, '12345')).toThrow('Secret key string must be in hex format')
      expect(() => crypto.encryptAB(message, keypairB.publicKey, 'zzz')).toThrow('Secret key string must be in hex format')
    })

    it('should throw error when decrypting with invalid message type', () => {
      const keypairA = crypto.generateKeypair()
      const keypairB = crypto.generateKeypair()

      expect(() => crypto.decryptAB(123, keypairA.publicKey, keypairB.secretKey)).toThrow('Message to decrypt must be a string')
      expect(() => crypto.decryptAB(null, keypairA.publicKey, keypairB.secretKey)).toThrow('Message to decrypt must be a string')
      expect(() => crypto.decryptAB(undefined, keypairA.publicKey, keypairB.secretKey)).toThrow('Message to decrypt must be a string')
      expect(() => crypto.decryptAB({}, keypairA.publicKey, keypairB.secretKey)).toThrow('Message to decrypt must be a string')
    })

    it('should throw error when decrypting with invalid message format', () => {
      const keypairA = crypto.generateKeypair()
      const keypairB = crypto.generateKeypair()

      // Missing colon separator
      expect(() => crypto.decryptAB('invalidformat', keypairA.publicKey, keypairB.secretKey)).toThrow('Message to decrypt in must have nonce:ciphertext as hex:base64')
      
      // Invalid nonce (not hex)
      expect(() => crypto.decryptAB('zzz:validbase64', keypairA.publicKey, keypairB.secretKey)).toThrow('Message to decrypt in must have nonce:ciphertext as hex:base64')
      
      // Invalid ciphertext (not base64)
      expect(() => crypto.decryptAB('a1b2c3:@@@###', keypairA.publicKey, keypairB.secretKey)).toThrow('Message to decrypt in must have nonce:ciphertext as hex:base64')
    })

    it('should throw error when decrypting with invalid public key format', () => {
      const keypairA = crypto.generateKeypair()
      const keypairB = crypto.generateKeypair()
      // First create a valid encrypted message to get the format right
      const encrypted = crypto.encryptAB('test', keypairB.publicKey, keypairA.secretKey)

      expect(() => crypto.decryptAB(encrypted, 'invalid', keypairB.secretKey)).toThrow('Secret key string must be in hex format')
      expect(() => crypto.decryptAB(encrypted, '12345', keypairB.secretKey)).toThrow('Secret key string must be in hex format')
      expect(() => crypto.decryptAB(encrypted, 'zzz', keypairB.secretKey)).toThrow('Secret key string must be in hex format')
    })

    it('should throw error when decrypting with invalid secret key format', () => {
      const keypairA = crypto.generateKeypair()
      const keypairB = crypto.generateKeypair()
      // First create a valid encrypted message to get the format right
      const encrypted = crypto.encryptAB('test', keypairB.publicKey, keypairA.secretKey)

      expect(() => crypto.decryptAB(encrypted, keypairA.publicKey, 'invalid')).toThrow('Secret key string must be in hex format')
      expect(() => crypto.decryptAB(encrypted, keypairA.publicKey, '12345')).toThrow('Secret key string must be in hex format')
      expect(() => crypto.decryptAB(encrypted, keypairA.publicKey, 'zzz')).toThrow('Secret key string must be in hex format')
    })

    it('should throw error when decrypting with wrong keys', () => {
      const keypairA = crypto.generateKeypair()
      const keypairB = crypto.generateKeypair()
      const keypairC = crypto.generateKeypair()
      const message = 'test message'

      // A encrypts for B
      const encrypted = crypto.encryptAB(message, keypairB.publicKey, keypairA.secretKey)

      // C tries to decrypt (should fail)
      expect(() => crypto.decryptAB(encrypted, keypairA.publicKey, keypairC.secretKey)).toThrow('Could not decrypt the message')
      
      // B tries to decrypt with wrong public key (should fail)
      expect(() => crypto.decryptAB(encrypted, keypairC.publicKey, keypairB.secretKey)).toThrow('Could not decrypt the message')
    })

    it('should throw error when decrypting corrupted ciphertext', () => {
      const keypairA = crypto.generateKeypair()
      const keypairB = crypto.generateKeypair()
      const message = 'test message'

      const encrypted = crypto.encryptAB(message, keypairB.publicKey, keypairA.secretKey)
      
      // Corrupt the ciphertext by modifying one character in the base64 part
      const parts = encrypted.split(':')
      const base64Part = parts[1]
      // Change a character in the middle of the base64 string
      const corruptedBase64 = base64Part.substring(0, 10) + 'X' + base64Part.substring(11)
      const corruptedEncrypted = parts[0] + ':' + corruptedBase64

      expect(() => crypto.decryptAB(corruptedEncrypted, keypairA.publicKey, keypairB.secretKey)).toThrow('Could not decrypt the message')
    })
  })
})
