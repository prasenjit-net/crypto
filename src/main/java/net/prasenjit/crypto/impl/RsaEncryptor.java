/*
 *    Copyright 2017 Prasenjit Purohit
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package net.prasenjit.crypto.impl;

import net.prasenjit.crypto.TextEncryptor;
import net.prasenjit.crypto.exception.CryptoException;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.util.Base64;

/**
 * Created by prase on 10-06-2017.
 */
public class RsaEncryptor implements TextEncryptor {
    private final static String ALGORITHM = "RSA";
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RsaEncryptor(PrivateKey privateKey) {
        this.privateKey = privateKey;
        if (!(privateKey instanceof RSAKey)) {
            throw new CryptoException("Only RSA keys are supported with RsaEncryptor");
        }
    }

    public RsaEncryptor(PublicKey publicKey) {
        this.publicKey = publicKey;
        if (!(publicKey instanceof RSAKey)) {
            throw new CryptoException("Only RSA keys are supported with RsaEncryptor");
        }
    }

    public RsaEncryptor(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        if (!(publicKey instanceof RSAKey)) {
            throw new CryptoException("Only RSA keys are supported with RsaEncryptor");
        }
        this.privateKey = privateKey;
        if (!(privateKey instanceof RSAKey)) {
            throw new CryptoException("Only RSA keys are supported with RsaEncryptor");
        }
    }

    @Override
    public byte[] encrypt(byte[] data) {
        if (publicKey == null) {
            throw new CryptoException("PublicKey not found for encryption");
        }
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(data);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException |
                InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new CryptoException("Encryption failed", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] data) {
        if (privateKey == null) {
            throw new CryptoException("PrivateKey not found for decryption");
        }
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(data);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException |
                InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new CryptoException("Decryption failed", e);
        }
    }

    public String wrapKey(SecretKey keyToWrap) {
        if (publicKey == null) {
            throw new CryptoException("PublicKey not found for encryption");
        }
        try {
            Cipher wrapper = Cipher.getInstance(ALGORITHM);
            wrapper.init(Cipher.WRAP_MODE, publicKey);
            byte[] wrappedKey = wrapper.wrap(keyToWrap);
            return Base64.getEncoder().encodeToString(wrappedKey);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | InvalidKeyException e) {
            throw new CryptoException("Failed to wrap key", e);
        }
    }

    public SecretKey unwrapKey(String wrappedKey) {
        if (privateKey == null) {
            throw new CryptoException("PrivateKey not found for decryption");
        }
        try {
            Cipher wrapper = Cipher.getInstance(ALGORITHM);
            wrapper.init(Cipher.UNWRAP_MODE, privateKey);
            byte[] wrappedByte = Base64.getDecoder().decode(wrappedKey);
            return (SecretKey) wrapper.unwrap(wrappedByte, "AES", Cipher.SECRET_KEY);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new CryptoException("Failed to wrap key", e);
        }
    }
}
