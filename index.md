# Get started with Crypto

## Encryptor

`net.prasenjit.crypto.Encryptor` is the base interface for all Encryption related features. It has two method like `encrypt` and `decrypt`.

## Text Encryptor

`net.prasenjit.crypto.TextEncryptor` is used to encrypt arbitary text or binary data. It extends `Encryptor`. It has additional method for text encoding.

## E2eEncryptor

`net.prasenjit.crypto.E2eEncryptor` is a interface to perform `end to end` encryption typically required in many high secure system where password is required to be encrypted from browser to end authentication system for total security.

## PasswordEncryptor
`net.prasenjit.crypto.PasswordEncryptor` is a special dygestor, which digest password to store in DB. And also it perform matching of password. This digested password is a one way transform and typically can never be converted to clear password.

## SignerVerifier
`net.prasenjit.crypto.SignerVerifier` is a interface to perform data signing and verification. It has method like `sign` and `verify`.

## AesEncryptor
`net.prasenjit.crypto.impl.AesEncryptor` is a implementation of symetric data encryption. It can be used in this way

```
KeyGenerator generator = KeyGenerator.getInstance("AES");
generator.init(128);
SecretKey secretKey = generator.generateKey();
TextEncryptor encryptor = new AesEncryptor(secretKey);
String data = "Hello World!";
String encrypted = encryptor.encrypt(data);
String decrypted = encryptor.decrypt(encrypted);
assertEquals(data, decrypted);
```
