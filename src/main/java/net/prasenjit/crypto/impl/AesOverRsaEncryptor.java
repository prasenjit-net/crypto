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

import net.prasenjit.crypto.E2eEncryptor;
import net.prasenjit.crypto.exception.CryptoException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * Created by prase on 17-06-2017.
 *
 * @author prasenjit
 * @version $Id: $Id
 */
public class AesOverRsaEncryptor implements E2eEncryptor {
    private final SecretKey secretKey;
    private final AesEncryptor aesEncryptor;
    private final RsaEncryptor rsaEncryptor;
    private boolean serverMode = true;

    /**
     * <p>Constructor for AesOverRsaEncryptor.</p>
     *
     * @param rsaEncryptor a {@link net.prasenjit.crypto.impl.RsaEncryptor} object.
     */
    public AesOverRsaEncryptor(RsaEncryptor rsaEncryptor) {
        this.rsaEncryptor = rsaEncryptor;
        this.serverMode = false;
        try {
            secretKey = KeyGenerator.getInstance("AES").generateKey();
            this.aesEncryptor = new AesEncryptor(secretKey);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Failed to generate AES key");
        }
    }

    /**
     * <p>Constructor for AesOverRsaEncryptor.</p>
     *
     * @param rsaEncryptor a {@link net.prasenjit.crypto.impl.RsaEncryptor} object.
     * @param encodedAesKey a {@link java.lang.String} object.
     */
    public AesOverRsaEncryptor(RsaEncryptor rsaEncryptor, String encodedAesKey) {
        this.rsaEncryptor = rsaEncryptor;
        secretKey = rsaEncryptor.unwrapKey(encodedAesKey, "AES", Cipher.SECRET_KEY);
        this.aesEncryptor = new AesEncryptor(secretKey);
    }

    /** {@inheritDoc} */
    @Override
    public String getEncryptedKey() {
        if (serverMode) {
            throw new CryptoException("Unsupported operation for E2E server");
        }
        return this.rsaEncryptor.wrapKey(secretKey);
    }

    /** {@inheritDoc} */
    @Override
    public byte[] encrypt(byte[] data) {
        return this.aesEncryptor.encrypt(data);
    }

    /** {@inheritDoc} */
    @Override
    public byte[] decrypt(byte[] data) {
        return this.aesEncryptor.decrypt(data);
    }

    /** {@inheritDoc} */
    @Override
    public String wrapKey(Key key) {
        return this.rsaEncryptor.wrapKey(key);
    }

    /** {@inheritDoc} */
    @Override
    public Key unwrapKey(String encryptedKey, String algorithm, int type) {
        return this.rsaEncryptor.unwrapKey(encryptedKey, algorithm, type);
    }
}
