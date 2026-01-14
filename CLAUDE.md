# CLAUDE.md - AI Assistant Guide for Crypto Library

## Project Overview

**Project Name:** Crypto
**Description:** A cryptographic operations utility library designed to introduce beginners to cryptography while serving as a production-ready library for enterprise security requirements.
**License:** Apache License 2.0
**Current Version:** 1.6.2-SNAPSHOT
**Group ID:** io.github.prasenjit-net
**Philosophy:** Power lies in simplicity

This library provides simple, easy-to-use abstractions over Java's complex cryptography APIs, supporting symmetric encryption (AES, 3DES), asymmetric encryption (RSA), password hashing (PBKDF2, SSHA), digital signatures, and hybrid end-to-end encryption patterns.

## Technology Stack

- **Language:** Java 8+ (source compatibility: Java 1.8)
- **Build Tool:** Gradle 8.x with Kotlin DSL
- **Testing Framework:** JUnit 5 (Jupiter)
- **Logging:** SLF4J API (compile), Logback (test)
- **Publishing:** Maven Central via OSSRH (Sonatype)
- **CI/CD:** GitHub Actions
- **Signing:** GPG for artifact signing

## Repository Structure

```
/home/user/crypto/
├── src/
│   ├── main/java/net/prasenjit/crypto/
│   │   ├── Encryptor.java                    # Base encryption interface
│   │   ├── TextEncryptor.java                # String-based encryption
│   │   ├── KeyEncryptor.java                 # Key wrapping/unwrapping
│   │   ├── PasswordEncryptor.java            # Password hashing
│   │   ├── SignerVerifier.java               # Digital signatures
│   │   ├── E2eEncryptor.java                 # End-to-end encryption
│   │   ├── exception/
│   │   │   └── CryptoException.java          # Runtime crypto exception
│   │   ├── impl/                             # Concrete implementations
│   │   │   ├── RsaEncryptor.java             # RSA asymmetric
│   │   │   ├── AesEncryptor.java             # AES symmetric
│   │   │   ├── DesedeEncryptor.java          # 3DES symmetric
│   │   │   ├── PBEEncryptor.java             # Password-based encryption
│   │   │   ├── AbstractSymmetricEncryptor.java # Base for symmetric algos
│   │   │   ├── RsaSignerVerifier.java        # RSA signatures
│   │   │   ├── PBKDF2PasswordEncryptor.java  # PBKDF2 hashing
│   │   │   ├── SshaPasswordEncryptor.java    # SSHA hashing
│   │   │   └── AesOverRsaEncryptor.java      # Hybrid encryption
│   │   ├── store/
│   │   │   └── CryptoKeyFactory.java         # Keystore management
│   │   └── endtoend/
│   │       ├── RsaEncryptorBuilder.java      # Builder for RSA
│   │       └── AesOverRsaEncryptorBuilder.java # Builder for hybrid E2E
│   └── test/java/net/prasenjit/crypto/
│       ├── impl/                             # Implementation tests
│       ├── endtoend/                         # E2E pattern tests
│       └── store/                            # Keystore tests
├── .github/workflows/                        # CI/CD pipelines
├── gradle/                                   # Gradle wrapper + version catalog
├── build.gradle.kts                          # Build configuration
├── settings.gradle.kts                       # Project settings
├── gradle.properties                         # Version properties
├── pom.xml                                   # Maven compatibility
├── crypto.jks                                # Keystore for examples
└── LICENSE                                   # Apache 2.0 license

Test Resources:
├── src/test/resources/test.jks              # Test keystore (password: test)
├── src/test/resources/advanced.jceks        # Advanced keystore (password: advanced)
└── src/test/resources/invalid_jks.txt       # Invalid file for error testing
```

## Architecture & Design Patterns

### Layered Architecture

```
Application Layer
      ↓
Builders (RsaEncryptorBuilder, AesOverRsaEncryptorBuilder)
      ↓
Interfaces (Encryptor, TextEncryptor, PasswordEncryptor, SignerVerifier)
      ↓
Implementations (RsaEncryptor, AesEncryptor, PBKDF2PasswordEncryptor, etc.)
      ↓
Storage (CryptoKeyFactory wrapping Java KeyStore)
      ↓
Java Crypto API (javax.crypto.*, java.security.*)
```

### Design Patterns

1. **Builder Pattern**
   - `CryptoKeyFactory.CryptoKeyFactoryBuilder` for keystore configuration
   - `RsaEncryptorBuilder` and `AesOverRsaEncryptorBuilder` for E2E setup
   - Static factory methods: `client()`, `server()`

2. **Factory Pattern**
   - Builder classes provide static factory methods
   - Encapsulates complex initialization logic

3. **Composition Pattern**
   - `AesOverRsaEncryptor` composes `RsaEncryptor` + `AesEncryptor`
   - Hybrid encryption without inheritance coupling

4. **Template Method Pattern**
   - `AbstractSymmetricEncryptor` provides base encryption logic
   - Subclasses provide algorithm-specific configuration

5. **Strategy Pattern**
   - Multiple `PasswordEncryptor` implementations (PBKDF2, SSHA, PBE)
   - Interchangeable encryption algorithms via interface

6. **Lazy Initialization**
   - `CryptoKeyFactory` uses synchronized lazy loading for keystores
   - Prevents unnecessary file I/O until needed

### Interface Hierarchy

```
Encryptor (byte[] encrypt/decrypt)
    └── TextEncryptor (String encrypt/decrypt + charset support)
        └── E2eEncryptor (+ getEncryptedKey() for key exchange)

KeyEncryptor (Key wrap/unwrap)
    └── Implemented by TextEncryptor implementations

PasswordEncryptor (encrypt/testMatch for password hashing)
    ├── PBKDF2PasswordEncryptor
    ├── SshaPasswordEncryptor
    └── PBEEncryptor

SignerVerifier (sign/verify)
    └── RsaSignerVerifier
```

## Key Components

### Core Interfaces

#### Encryptor
- **Purpose:** Base interface for byte-level encryption/decryption
- **Methods:** `byte[] encrypt(byte[])`, `byte[] decrypt(byte[])`
- **Implementations:** All encryption classes

#### TextEncryptor
- **Purpose:** String-based encryption with charset and Base64 support
- **Extends:** `Encryptor`, `KeyEncryptor`
- **Methods:**
  - `String encrypt(String, Charset)` - Returns Base64-encoded ciphertext
  - `String decrypt(String, Charset)` - Accepts Base64-encoded input
- **Implementations:** `RsaEncryptor`, `AesEncryptor`, `DesedeEncryptor`, `PBEEncryptor`, `AesOverRsaEncryptor`

#### PasswordEncryptor
- **Purpose:** One-way password hashing with verification
- **Methods:**
  - `String encrypt(String)` - Hash password, return Base64
  - `boolean testMatch(String plain, String hashed)` - Verify password
- **Implementations:** `PBKDF2PasswordEncryptor`, `SshaPasswordEncryptor`, `PBEEncryptor`

#### E2eEncryptor
- **Purpose:** End-to-end encryption with shared key exposure
- **Extends:** `TextEncryptor`
- **Methods:** `String getEncryptedKey()` - Returns RSA-encrypted AES key for transport
- **Implementation:** `AesOverRsaEncryptor`

### Implementation Details

#### AbstractSymmetricEncryptor
- **Base class for:** `AesEncryptor`, `DesedeEncryptor`
- **IV Handling:**
  - Generates random IV per encryption using `SecureRandom`
  - Appends IV to ciphertext during encryption
  - Extracts IV from ciphertext during decryption
  - No separate IV parameter required for decryption
- **Algorithm:** Configurable via constructor (e.g., "AES/CBC/PKCS5Padding")

#### RsaEncryptor
- **Type:** Asymmetric encryption
- **Key Requirements:**
  - Encryption: Public key (RSAPublicKey)
  - Decryption: Private key (RSAPrivateKey)
- **Key Wrapping:**
  - Uses `Cipher.WRAP_MODE` and `UNWRAP_MODE`
  - Returns Base64-encoded wrapped keys

#### AesOverRsaEncryptor
- **Type:** Hybrid encryption (combines RSA + AES)
- **Pattern:**
  - **Client Mode:** Generates AES key, encrypts data with AES, exposes RSA-encrypted AES key
  - **Server Mode:** Receives encrypted AES key, decrypts with RSA private key, uses for AES encryption
- **Benefits:**
  - RSA security for key exchange
  - AES performance for bulk data
- **Composition:** Wraps `RsaEncryptor` and `AesEncryptor` instances

#### PBKDF2PasswordEncryptor
- **Algorithm:** PBKDF2WithHmacSHA1
- **Configuration:** Configurable iterations (default: 1000) and salt size (default: 8 bytes)
- **Salt Handling:** Random salt generated, appended to hash output
- **Output:** Base64-encoded (salt + hash)

#### SshaPasswordEncryptor
- **Algorithm:** SHA-256 with salt
- **Salt:** 8-byte random salt via `SecureRandom`
- **Output:** Base64-encoded (hash + salt)

#### CryptoKeyFactory
- **Purpose:** Unified keystore access with builder pattern
- **Supported Types:** JKS, JCEKS, custom providers
- **Methods:**
  - `getPublicKey(String alias)`
  - `getPrivateKey(String alias, char[] password)`
  - `getSecretKey(String alias, char[] password)`
  - `getKeyPair(String alias, char[] password)`
  - `getCertificate(String alias)`
- **Builder Options:**
  - `location(URI)` - Keystore file location
  - `password(char[])` - Keystore password (default: "changeit")
  - `provider(String)` - Security provider
  - `type(String)` - Keystore type (default: KeyStore.getDefaultType())
- **Lazy Loading:** Keystore loaded only on first access (synchronized)

## Development Workflow

### Version Management

- **Current Version:** Defined in `gradle.properties` (1.6.2-SNAPSHOT)
- **Versioning:** Semantic versioning (major.minor.patch)
- **Release Plugin:** `net.researchgate.release` v3.0.2
- **Branch Requirement:** Releases must be on `master` branch

### Dependency Management

**Version Catalog** (`gradle/libs.versions.toml`):
```toml
[versions]
slf4j = "1.7.30"
logback = "1.4.12"
junit = "5.7.2"

[bundles]
compile = ["slf4j-api"]
test = ["junit-jupiter-api", "junit-jupiter-engine", "logback-core"]
```

### Build Commands

```bash
# Build project
./gradlew build

# Run tests
./gradlew test

# Clean build
./gradlew clean build

# Generate Javadoc
./gradlew javadoc

# Publish to local Maven repository
./gradlew publishToMavenLocal

# Check dependency updates
./gradlew dependencyUpdates

# Create release (via Gradle Release Plugin)
./gradlew release -Prelease.releaseVersion=1.6.2 -Prelease.newVersion=1.6.3-SNAPSHOT
```

## Build & Testing

### Build Configuration

**build.gradle.kts Key Features:**
- Java 8 source compatibility
- Generates sources and Javadoc JARs automatically
- Maven Central publishing via OSSRH
- GPG signing (CI: `useGpgCmd()`, local: optional)
- JAR manifest with Implementation-Title/Version/Description
- JUnit Platform for test execution

### Testing Approach

**Framework:** JUnit 5 (Jupiter)

**Test Coverage:**
- 10 test classes covering all major implementations
- Round-trip validation (encrypt → decrypt → assertEquals)
- Key wrap/unwrap verification
- Exception testing with `assertThrows()`
- Builder pattern testing
- Negative testing (invalid keystores, missing keys)

**Test Resources:**
- `test.jks` - JKS keystore (password: "test")
- `advanced.jceks` - JCEKS keystore (password: "advanced")
- `invalid_jks.txt` - Invalid file for error testing

**Test Patterns:**
```java
@BeforeEach
void setUp() {
    // Key generation, encryptor initialization
}

@Test
void testEncryptDecrypt() {
    // Round-trip test
    String original = "test data";
    String encrypted = encryptor.encrypt(original, StandardCharsets.UTF_8);
    String decrypted = encryptor.decrypt(encrypted, StandardCharsets.UTF_8);
    assertEquals(original, decrypted);
}
```

### Running Tests

```bash
# Run all tests
./gradlew test

# Run specific test class
./gradlew test --tests AesEncryptorTest

# Run with test report
./gradlew test --info

# Run tests with coverage (if configured)
./gradlew test jacocoTestReport
```

## CI/CD Pipeline

### GitHub Actions Workflows

**Main Pipeline** (`pipeline.yml`):
- **Triggers:**
  - Push to `master` branch
  - Git tags
  - Pull requests
  - Manual workflow dispatch for releases
- **Jobs:**
  1. **Build:** Compile + run JUnit tests
  2. **Gradle Release:** Create versioned release (manual trigger)
  3. **Publish Sonatype:** Publish SNAPSHOTs (master) or releases (tags)

**Callable Workflows:**

1. **callable.build.yml**
   - Java 21 (Corretto distribution)
   - Gradle wrapper validation
   - Build with tests
   - JUnit test report publishing

2. **callable.gradle-release.yml**
   - Validates release type (major/minor/patch)
   - Checks out master branch
   - Runs `./gradlew release`

3. **callable.publish-sonatype.yml**
   - GPG signing configuration
   - SNAPSHOT publishing to OSSRH
   - Release publishing to Maven Central

### Publishing

**Repositories:**
- **SNAPSHOT:** https://oss.sonatype.org/content/repositories/snapshots/
- **Release:** https://oss.sonatype.org/service/local/staging/deploy/maven2/

**Credentials:** Stored in GitHub Secrets
- `REPO_USERNAME` / `REPO_PASSWORD` for Sonatype
- GPG keys for artifact signing

## Code Conventions

### Naming Conventions

- **Interfaces:** `Encryptor`, `TextEncryptor`, `PasswordEncryptor`, `SignerVerifier`
- **Implementations:** Concrete algorithm names (`RsaEncryptor`, `AesEncryptor`, `PBKDF2PasswordEncryptor`)
- **Builders:** `*Builder` or `*EncryptorBuilder` suffix
- **Exceptions:** `*Exception` suffix (e.g., `CryptoException`)
- **Abstract Classes:** `Abstract*` prefix (e.g., `AbstractSymmetricEncryptor`)
- **Packages:** Lowercase, hierarchical (`net.prasenjit.crypto.impl`, `net.prasenjit.crypto.store`)

### File Structure

**Every source file includes:**
1. Apache License 2.0 header (lines 1-15)
2. Package declaration
3. Imports
4. Class-level Javadoc with `@author` and `@version`
5. Class implementation

**Package Documentation:**
- Every package has `package-info.java`
- Documents package purpose and access notes
- Example: `impl` package marked "should not be accessed directly"

### Javadoc Standards

**Class Level:**
```java
/**
 * <p>Brief description of class purpose.</p>
 *
 * <p>Additional details and usage notes.</p>
 *
 * Created by prase on DD-MM-YYYY.
 *
 * @author prasenjit
 * @version $Id: $Id
 */
```

**Method Level:**
```java
/**
 * <p>Method description.</p>
 *
 * @param paramName a {@link Type} description of parameter.
 * @return a {@link ReturnType} description of return value.
 * @throws ExceptionType if error condition.
 * @since 1.1
 */
```

### Error Handling

- **Exception Type:** `CryptoException` (unchecked, extends `RuntimeException`)
- **Wrapping:** All checked crypto exceptions wrapped in `CryptoException`
- **Messages:** Descriptive context ("Encryption failed", "Failed to extract public key")
- **No Silent Failures:** All crypto errors propagated to caller

### Security Patterns

1. **Random Generation:** Use `SecureRandom` for IVs, salts, keys
2. **IV Management:** Never hardcode IVs; generate per encryption, append to ciphertext
3. **Salt Management:** Random salt per password hash, appended to output
4. **Key Validation:** Verify key types at construction (`instanceof` checks)
5. **Constant-Time Comparison:** Use `Arrays.equals()` for password verification
6. **Lazy Loading:** Load keystores only when needed
7. **No Key Logging:** Never log sensitive key material

### Code Style

- **Indentation:** Standard Java (4 spaces or tabs, consistent with codebase)
- **Braces:** Egyptian style (opening brace on same line)
- **Line Length:** Reasonable (no strict limit, but avoid overly long lines)
- **Imports:** Organized, no wildcards for specific classes
- **Modifiers:** `public`, `private`, `protected` explicitly declared
- **Final:** Use for immutable fields and parameters where appropriate

## Common Tasks for AI Assistants

### Adding a New Encryption Algorithm

1. **Create Implementation Class** in `src/main/java/net/prasenjit/crypto/impl/`
   - Extend `AbstractSymmetricEncryptor` (if symmetric) or implement `TextEncryptor` directly
   - Add Apache license header
   - Include class-level Javadoc
   - Implement required methods

2. **Create Test Class** in `src/test/java/net/prasenjit/crypto/impl/`
   - Extend JUnit 5 test class
   - Add `@BeforeEach` setup method
   - Write round-trip tests
   - Test key wrapping if applicable
   - Test edge cases and exceptions

3. **Update Documentation**
   - Add entry to README.md if user-facing
   - Update package-info.java if new package

4. **Run Tests**
   ```bash
   ./gradlew test --tests YourNewEncryptorTest
   ./gradlew test  # All tests must pass
   ```

### Adding a New Builder

1. **Create Builder Class** in `src/main/java/net/prasenjit/crypto/endtoend/`
2. **Implement Static Factory Methods:** `client()`, `server()`, etc.
3. **Add Comprehensive Tests** with E2E workflow validation
4. **Document Usage Patterns** in Javadoc

### Updating Dependencies

1. **Edit** `gradle/libs.versions.toml`
2. **Update Version Numbers** in `[versions]` section
3. **Run Dependency Update Check:**
   ```bash
   ./gradlew dependencyUpdates
   ```
4. **Test Build:**
   ```bash
   ./gradlew clean build
   ```
5. **Run All Tests:**
   ```bash
   ./gradlew test
   ```

### Creating a Release

**Via GitHub Actions (Recommended):**
1. Navigate to Actions → Main Pipeline
2. Click "Run workflow"
3. Select release type: `major`, `minor`, or `patch`
4. Workflow will:
   - Build and test
   - Update version in `gradle.properties`
   - Create git tag
   - Publish to Maven Central

**Via Gradle (Manual):**
```bash
./gradlew release -Prelease.releaseVersion=X.Y.Z -Prelease.newVersion=X.Y.Z+1-SNAPSHOT
```

### Investigating Test Failures

1. **Run Failed Test with Details:**
   ```bash
   ./gradlew test --tests FailingTest --info
   ```

2. **Check Test Reports:**
   - Location: `build/reports/tests/test/index.html`
   - Open in browser for detailed failure info

3. **Common Issues:**
   - Keystore password mismatch (check test resources)
   - Missing test keystore files
   - Key size restrictions (check JCE unlimited strength)
   - Platform-specific crypto provider issues

### Debugging Encryption Issues

1. **Verify Key Types:**
   ```java
   if (!(key instanceof RSAPublicKey)) {
       throw new CryptoException("Invalid key type");
   }
   ```

2. **Check IV Handling:** Ensure IV is appended/extracted correctly
3. **Validate Base64 Encoding:** Ensure consistent encoding/decoding
4. **Test with Known Values:** Use test vectors from standards
5. **Check Algorithm String:** Verify "AES/CBC/PKCS5Padding" format

### Code Review Checklist

- [ ] Apache license header present
- [ ] Javadoc complete with `@param`, `@return`, `@throws`
- [ ] Exception handling wraps in `CryptoException`
- [ ] Tests added with `@Test` annotation
- [ ] Round-trip encryption/decryption tested
- [ ] Edge cases tested (null, empty, invalid input)
- [ ] No hardcoded secrets or keys
- [ ] SecureRandom used for random values
- [ ] No security vulnerabilities introduced
- [ ] Code follows existing patterns
- [ ] Build passes: `./gradlew build`
- [ ] All tests pass: `./gradlew test`

## Important Notes for AI Assistants

### DO

- ✅ **Read existing code** before making changes to understand patterns
- ✅ **Follow existing conventions** (naming, structure, Javadoc)
- ✅ **Write comprehensive tests** for all new functionality
- ✅ **Use SecureRandom** for all random value generation
- ✅ **Wrap checked exceptions** in `CryptoException`
- ✅ **Add Apache license headers** to all new files
- ✅ **Document all public APIs** with Javadoc
- ✅ **Validate input parameters** (null checks, type validation)
- ✅ **Run tests before committing** (`./gradlew test`)
- ✅ **Keep it simple** - this library's power is in simplicity
- ✅ **Test round-trip operations** (encrypt then decrypt)
- ✅ **Use builders** for complex object creation

### DON'T

- ❌ **Don't hardcode IVs or salts** - generate randomly per operation
- ❌ **Don't log sensitive data** (keys, plaintext, passwords)
- ❌ **Don't skip tests** - all changes must be tested
- ❌ **Don't use weak algorithms** without security warnings
- ❌ **Don't break backwards compatibility** without version bump
- ❌ **Don't access `impl` package directly** in examples
- ❌ **Don't use wildcards in imports** for specific classes
- ❌ **Don't commit keystores with real credentials**
- ❌ **Don't modify license headers**
- ❌ **Don't over-engineer** - keep solutions simple
- ❌ **Don't push to master** - use feature branches
- ❌ **Don't release without GPG signing**

### Security Considerations

1. **Key Management:**
   - Never log private keys or secret keys
   - Validate key types before use
   - Clear sensitive data from memory when possible

2. **Random Values:**
   - Always use `SecureRandom`, never `Random`
   - Generate new IV per encryption operation
   - Use sufficient salt size (minimum 8 bytes)

3. **Algorithm Selection:**
   - Prefer AES over DES/3DES for symmetric encryption
   - Use RSA with appropriate key sizes (2048+ bits)
   - Use PBKDF2 with high iteration counts (10,000+)

4. **Error Messages:**
   - Don't reveal sensitive information in exceptions
   - Avoid timing attacks in password verification

5. **Testing:**
   - Test keystores are for testing only
   - Don't commit real credentials
   - Use test-specific passwords

### Common Pitfalls

1. **IV Handling:** Forgetting to append/extract IV from ciphertext
2. **Base64 Encoding:** Inconsistent encoding between encrypt/decrypt
3. **Key Validation:** Not checking key types before use
4. **Exception Wrapping:** Letting checked exceptions propagate
5. **Test Resources:** Missing or incorrect keystore passwords
6. **Charset Handling:** Inconsistent charset usage in String operations
7. **Salt Extraction:** Incorrect byte array slicing in password verification

### File References

When referencing code locations, use this format:
- `net.prasenjit.crypto.impl.AesEncryptor:45` (class:line)
- `src/main/java/net/prasenjit/crypto/Encryptor.java:23` (file:line)

### Git Workflow

**Branch Strategy:**
- `master` - Main branch, requires releases
- Feature branches - `feature/description` or `claude/description-{sessionId}`
- Release branches created by Gradle Release Plugin

**Commit Messages:**
```
[type]: Brief description

Detailed explanation if needed.

Fixes #issue-number
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `build`

**Before Pushing:**
```bash
./gradlew clean build test  # Ensure all tests pass
git status                  # Review changes
git add <files>             # Stage specific files
git commit -m "message"     # Commit with clear message
git push -u origin branch   # Push to feature branch
```

### Contact & Resources

- **Repository:** https://github.com/prasenjit-net/crypto
- **Maven Central:** https://search.maven.org/search?q=g:net.prasenjit%20AND%20a:crypto
- **Issues:** https://github.com/prasenjit-net/crypto/issues
- **Author:** Prasenjit Purohit (prasenjit@prasenjit.net)
- **Website:** https://www.prasenjit.net/crypto/

---

**Last Updated:** 2026-01-14
**Version:** 1.6.2-SNAPSHOT
**Document Maintainer:** AI Assistant
