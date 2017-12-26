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

`net.prasenjit.crypto.impl.AesEncryptor` is a implementation of symetric data encryption which uses a AES key. It can be used in this way

```java
KeyGenerator generator = KeyGenerator.getInstance("AES");
generator.init(128);
SecretKey secretKey = generator.generateKey();
TextEncryptor encryptor = new AesEncryptor(secretKey);
String data = "Hello World!";
String encrypted = encryptor.encrypt(data);
String decrypted = encryptor.decrypt(encrypted);
assertEquals(data, decrypted);
```

### DesedeEncryptor

`net.prasenjit.crypto.impl.DesedeEncryptor` is a implementation of text encryptor which uses a 3DES key. It can be used in this way

```java
KeyGenerator generator = KeyGenerator.getInstance("DESede");
generator.init(168);
SecretKey secretKey = generator.generateKey();
DesedeEncryptor encryptor = new DesedeEncryptor(secretKey);
String data = "Hello World!";
String encrypted = encryptor.encrypt(data);
String decrypted = encryptor.decrypt(encrypted);
assertEquals(data, decrypted);
```

### PBEEncryptor
`net.prasenjit.crypto.impl.PBEEncryptor` is a password based text encryptor, it uses a user provided password instead of a secret key. It can be used in

```java
String data = "My precious data";
PBEEncryptor encryptor = new PBEEncryptor("password".toCharArray());
String encrypt = encryptor.encrypt(data);
String decrypt = encryptor.decrypt(encrypt);
assertEquals(data, decrypt);
```

## RSAEncryptor

`net.prasenjit.crypto.impl.RsaEncryptor` is a asymmetric key bases text incryption. It uses a pair of Private Key and Public Key to perform the encryption. Its public key is used for encryption and private key is used for decryption. A text when encrypted with public key, can only be decrypted by private key. The opposite way encryption is not supported here as that doesnt make any sence. It can be used in

```java
KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
generator.initialize(1024);
KeyPair keyPair = generator.generateKeyPair();
RsaEncryptor encryptor = new RsaEncryptor(keyPair.getPublic());
RsaEncryptor decryptor = new RsaEncryptor(keyPair.getPrivate());
String data = "Hello World!";
String encrypted = encryptor.encrypt(data);
String decrypted = decryptor.decrypt(encrypted);
assertEquals(data, decrypted);
```

