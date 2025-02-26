const crypto = require("../../index.js");

// Test hash key for initialization
const TEST_HASH_KEY =
  "64f152869ca2d473e4ba64ab53f49ccdb2edae22da192c126850970e788af347";

// Mock console.log to prevent output during tests
beforeAll(() => {
  jest.spyOn(console, "log").mockImplementation(() => {});
  jest.spyOn(console, "warn").mockImplementation(() => {});
  jest.spyOn(console, "error").mockImplementation(() => {});
});

afterAll(() => {
  jest.restoreAllMocks();
});

describe("Crypto Library", () => {
  const testHashKey =
    "69fa4195670576c0160d660c3be36556ff8d504725be8a59b5a96509e0c994bc";

  // Initialize the library before all tests
  beforeAll(async () => {
    await crypto.initialize(testHashKey);
  });

  describe("initialization", () => {
    it("should initialize successfully with a valid hash key", async () => {
      await expect(crypto.initialize(testHashKey)).resolves.not.toThrow();
    });

    it("should throw an error if hash key is invalid", async () => {
      await expect(crypto.initialize("invalid")).rejects.toThrow();
    });
  });

  describe("randomBytes", () => {
    it("should generate random bytes of default length (32)", () => {
      const bytes = crypto.randomBytes();
      expect(bytes).toHaveLength(64); // 32 bytes in hex is 64 characters
    });

    it("should generate random bytes of specified length", () => {
      const bytes = crypto.randomBytes(16);
      expect(bytes).toHaveLength(32); // 16 bytes in hex is 32 characters
    });

    it("should throw an error if bytes parameter is invalid", () => {
      expect(() => crypto.randomBytes("invalid")).toThrow();
    });
  });

  describe("hash", () => {
    it("should hash a string input and return a hex string by default", () => {
      const hash = crypto.hash("test");
      expect(typeof hash).toBe("string");
      expect(hash).toMatch(/^[0-9a-f]{64}$/); // 32 bytes in hex is 64 characters
    });

    it("should return consistent hash for the same input", () => {
      const hash1 = crypto.hash("test");
      const hash2 = crypto.hash("test");
      expect(hash1).toBe(hash2);
    });

    it("should return different hashes for different inputs", () => {
      const hash1 = crypto.hash("test1");
      const hash2 = crypto.hash("test2");
      expect(hash1).not.toBe(hash2);
    });

    it("should support uint8arr output format", () => {
      const hash = crypto.hash("test", "uint8arr");
      expect(hash).toBeInstanceOf(Uint8Array);
      expect(hash.length).toBe(32); // 32 bytes
    });

    it("should throw an error for invalid input type", () => {
      expect(() => crypto.hash(null)).toThrow();
    });

    it("should throw an error for invalid output format", () => {
      expect(() => crypto.hash("test", "invalid")).toThrow();
    });
  });

  describe("hashObj", () => {
    it("should hash an object and return a hex string", () => {
      const obj = { test: "value" };
      const hash = crypto.hashObj(obj);
      expect(typeof hash).toBe("string");
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it("should return consistent hash for the same object", () => {
      const obj = { test: "value" };
      const hash1 = crypto.hashObj(obj);
      const hash2 = crypto.hashObj(obj);
      expect(hash1).toBe(hash2);
    });

    it("should hash objects with properties in different order the same way", () => {
      const obj1 = { a: 1, b: 2 };
      const obj2 = { b: 2, a: 1 };
      const hash1 = crypto.hashObj(obj1);
      const hash2 = crypto.hashObj(obj2);
      expect(hash1).toBe(hash2);
    });

    it("should hash an object without the sign field when removeSign is true", () => {
      const obj = { test: "value", sign: { owner: "test", sig: "test" } };
      const hashWithSign = crypto.hashObj(obj, false);
      const hashWithoutSign = crypto.hashObj(obj, true);
      expect(hashWithSign).not.toBe(hashWithoutSign);
    });

    it("should throw an error for invalid input type", () => {
      expect(() => crypto.hashObj("not an object")).toThrow();
    });

    it("should throw an error when removeSign is true but object has no sign field", () => {
      const obj = { test: "value" };
      expect(() => crypto.hashObj(obj, true)).toThrow();
    });
  });

  describe("generateKeypair", () => {
    it("should generate a keypair with publicKey and secretKey", () => {
      const keypair = crypto.generateKeypair();
      expect(keypair).toHaveProperty("publicKey");
      expect(keypair).toHaveProperty("secretKey");
      expect(keypair.publicKey).toMatch(/^[0-9a-f]{64}$/);
      expect(keypair.secretKey).toMatch(/^[0-9a-f]{128}$/);
    });
  });

  describe("sign and verify", () => {
    it("should sign a message hash and verify it successfully", () => {
      const keypair = crypto.generateKeypair();
      const message = "test message";
      const messageHash = crypto.hash(message);

      const signature = crypto.sign(messageHash, keypair.secretKey);
      // The signature length can vary, but it should be a hex string
      expect(typeof signature).toBe("string");
      expect(signature).toMatch(/^[0-9a-f]+$/);

      const verified = crypto.verify(messageHash, signature, keypair.publicKey);
      expect(verified).toBe(true);
    });

    it("should fail verification with incorrect message", () => {
      const keypair = crypto.generateKeypair();
      const message1 = "test message";
      const message2 = "different message";
      const messageHash1 = crypto.hash(message1);
      const messageHash2 = crypto.hash(message2);

      const signature = crypto.sign(messageHash1, keypair.secretKey);

      // The verify function returns false for incorrect messages
      const verified = crypto.verify(
        messageHash2,
        signature,
        keypair.publicKey
      );
      expect(verified).toBe(false);
    });

    it("should fail verification with incorrect public key", () => {
      const keypair1 = crypto.generateKeypair();
      const keypair2 = crypto.generateKeypair();
      const message = "test message";
      const messageHash = crypto.hash(message);

      const signature = crypto.sign(messageHash, keypair1.secretKey);

      // The verify function throws an error when verification fails with wrong public key
      expect(() => {
        crypto.verify(messageHash, signature, keypair2.publicKey);
      }).toThrow(
        "Unable to verify provided signature with provided public key"
      );
    });
  });

  describe("signObj and verifyObj", () => {
    it("should sign an object and verify it successfully", () => {
      const keypair = crypto.generateKeypair();
      const obj = { test: "value" };

      crypto.signObj(obj, keypair.secretKey, keypair.publicKey);

      expect(obj).toHaveProperty("sign");
      expect(obj.sign).toHaveProperty("owner");
      expect(obj.sign).toHaveProperty("sig");
      expect(obj.sign.owner).toBe(keypair.publicKey);

      const verified = crypto.verifyObj(obj);
      expect(verified).toBe(true);
    });

    it("should fail verification if object is modified after signing", () => {
      const keypair = crypto.generateKeypair();
      const obj = { test: "value" };

      crypto.signObj(obj, keypair.secretKey, keypair.publicKey);
      obj.test = "modified";

      // verifyObj returns false when verification fails, not throws
      const verified = crypto.verifyObj(obj);
      expect(verified).toBe(false);
    });
  });
});
