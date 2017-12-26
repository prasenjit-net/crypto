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

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

/**
 * Created by prase on 17-06-2017.
 */
public class AesOverRsaEncryptor implements E2eEncryptor {
    private final SecretKey secretKey;
    private final AesEncryptor aesEncryptor;
    private final RsaEncryptor rsaEncryptor;
    private boolean serverMode = true;

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

    public AesOverRsaEncryptor(RsaEncryptor rsaEncryptor, String encodedAesKey) {
        this.rsaEncryptor = rsaEncryptor;
        secretKey = rsaEncryptor.unwrapKey(encodedAesKey);
        this.aesEncryptor = new AesEncryptor(secretKey);
    }

    @Override
    public String getEncryptedKey() {
        if (serverMode) {
            throw new CryptoException("Unsupported operation for E2E server");
        }
        return this.rsaEncryptor.wrapKey(secretKey);
    }

    @Override
    public byte[] encrypt(byte[] data) {
        return this.aesEncryptor.encrypt(data);
    }

    @Override
    public byte[] decrypt(byte[] data) {
        return this.aesEncryptor.decrypt(data);
    }
}
