# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a web crypto utilities library for the Shardus project, providing cryptographic functions using libsodium. The library is written in JavaScript with TypeScript support.

## Key Architecture Concepts

### Initialization Requirement
The library must be initialized with a 32-byte hex key before any crypto operations:
```javascript
crypto.initialize('64f152869ca2d473e4ba64ab53f49ccdb2edae22da192c126850970e788af347')
```

### Core Module Structure
- **index.js**: Single file containing all crypto functions (monolithic design)
- All functions are exported as a single object with method properties
- Uses libsodium-wrappers for underlying crypto operations
- Ed25519 keys for signing, converted to Curve25519 for encryption

### Object Serialization Pattern
- Objects are consistently serialized using `json-stable-stringify` before hashing/signing
- This ensures deterministic output regardless of object property order
- The `hashObj` and `signObj` functions handle object serialization automatically

## Development Commands

### Testing
```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage
```

### Building
```bash
# Compile TypeScript definitions
npm run compile
```

### Code Formatting
```bash
# Check formatting
npm run format-check

# Auto-fix formatting
npm run format-fix
```

### Release Process
```bash
# Create pre-release version
npm run release:pre

# Create patch/minor/major release
npm run release:patch
npm run release:minor  
npm run release:major
```

## Code Conventions

### Error Handling Pattern
All functions validate inputs and throw descriptive errors:
```javascript
if (!libsodium) throw new Error('You must call crypto.initialize()')
if (typeof obj !== 'object') throw new TypeError(`crypto.hashObj expected an object`)
```

### Function Input/Output
- Most functions accept strings (hex format) or objects
- Hash outputs can be 'hex' (default) or 'buffer' format
- Key generation returns object with `publicKey` and `secretKey` properties

### Testing Approach
- Unit tests in `test/unit/crypto.test.js`
- Tests cover initialization, all crypto operations, and error cases
- Mock the initialization key for testing: `64f152869ca2d473e4ba64ab53f49ccdb2edae22da192c126850970e788af347`

## Important Notes

1. **Libsodium Ready Check**: The code waits for libsodium to be ready before operations
2. **Key Format**: All keys are handled as hex strings in the API
3. **Signature Format**: Signatures are attached to objects as a `sign` property containing `owner` (public key) and `sig` (signature)
4. **Encryption Keys**: When encrypting/decrypting, the public/secret key pair must be from opposite parties (A encrypts with B's public key and A's secret key)