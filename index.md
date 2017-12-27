# Crypto - A Simple Encryption library

## Include This Library with Maven

To include this library as a dependency to your project use this coordinate.

```xml
<dependency>
  <groupId>net.prasenjit</groupId>
  <artifactId>crypto</artifactId>
  <version>1.1</version>
</dependency>
```

## Encryptor

`net.prasenjit.crypto.Encryptor` is the base interface for all Encryption related features. It has two method like `encrypt` and `decrypt`.

## TextEncryptor

`net.prasenjit.crypto.TextEncryptor` is used to encrypt arbitary text or binary data. It extends `Encryptor`. It has additional method for text encoding.

## E2eEncryptor

`net.prasenjit.crypto.E2eEncryptor` is a interface to perform `end to end` encryption typically required in many high secure system where password is required to be encrypted from browser to end authentication system for total security.

## PasswordEncryptor
`net.prasenjit.crypto.PasswordEncryptor` is a special dygester, which digest password to store in DB. And also it perform matching of password. This digested password is a one way transform and typically can never be converted to clear password.

## SignerVerifier
`net.prasenjit.crypto.SignerVerifier` is an interface to perform data signing and verification. It has method like `sign` and `verify`.

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

> This can only be used for small datas, as encrypting data larger that key length in vulnarable in RSA.

## RsaSignerVerifier

`net.prasenjit.crypto.impl.RsaSignerVerifier` is a data signer and verifier which use the RSA algorithm. Opposite way as RSA encription works. Its private ke is used to sign and public key can be used to verify a signature. Opposite to this is not supported. It can be used in

```java
KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
RsaSignerVerifier signerVerifier = new RsaSignerVerifier(keyPair.getPublic(), keyPair.getPrivate());
String data = "Hello World!";
String sign = signerVerifier.sign(data);
assertTrue(signerVerifier.verify(data, sign));
```

## SshaPasswordEncryptor

`net.prasenjit.crypto.impl.SshaPasswordEncryptor` is a password digestor which uses salted sha-256 algorithm. This is generally secure to store in DB. It can be used in

```java
PasswordEncryptor encryptor = new SshaPasswordEncryptor();
String plainPassword = "plain password";
String encrypted = encryptor.encrypt(plainPassword);
assertTrue(encryptor.testMatch(plainPassword, encrypted));
assertFalse(encryptor.testMatch(plainPassword + "1", encrypted));
```

## RsaEncryptorBuilder

`net.prasenjit.crypto.endtoend.RsaEncryptorBuilder` is a builder for RsaEncryptor to use in E2E scenario. It use a RSA key pair. Public key can be shared with client and private key is kept secret in server. A client can only encrypt data and server can decrypt that.It works in this way

. Server creates a RSA key pair and share that with client
. Now client can use the public key to encrypt data
. Which server can decrypt with private key

It can be used in

```java
String data = "Hello World!";
KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
TextEncryptor client = RsaEncryptorBuilder.client(keyPair.getPublic());
TextEncryptor server = RsaEncryptorBuilder.server(keyPair.getPrivate());
String output = server.decrypt(client.encrypt(data));
assertEquals(data, output);
```

> This can only be used for small data, as encrypting data larger that key length in vulnarable in RSA.
> And also it can be used in one way, means only client can encrypt and server can decrypt.

## AesOverRsaEncryptorBuilder

`net.prasenjit.crypto.endtoend.AesOverRsaEncryptorBuilder` is a E2E encryption builder which uses a AES key, shared with server encrypted in server´s public key. It works in this way

. Server creates a RSA key pair and share the public key with client
. Client creates a AES key, encrypt with public RSA and sends to server
. Server decrypts the AES key with private RSA key
. Now both can use AES key to encrypt and decrypt data

```java
String data = "Hello World!";
KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
E2eEncryptor client = AesOverRsaEncryptorBuilder.client(keyPair.getPublic());
E2eEncryptor server = AesOverRsaEncryptorBuilder.server(keyPair.getPrivate(), client.getEncryptedKey());
String result = server.decrypt(client.encrypt(data));
assertEquals(data, result);
result = client.decrypt(server.encrypt(data));
assertEquals(data, result);
```

> It can be used for lerger data as AES doesnt have such vulnarability.
> And also it can be used in both way, means only client and server both can encrypt/decrypt.