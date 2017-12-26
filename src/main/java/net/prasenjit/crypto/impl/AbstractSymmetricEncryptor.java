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
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Created by prase on 11-06-2017.
 */
public class AbstractSymmetricEncryptor implements TextEncryptor {
    private final String algorithm;
    private final SecretKey key;
    private final SecureRandom secureRandom = new SecureRandom();

    public AbstractSymmetricEncryptor(SecretKey key, String algorithm) {
        this.key = key;
        this.algorithm = algorithm;
    }

    @Override
    public byte[] encrypt(byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            int blockSize = cipher.getBlockSize();
            byte[] ivBytes = new byte[blockSize];
            secureRandom.nextBytes(ivBytes);
            final IvParameterSpec iv = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] encryptedBytes = cipher.doFinal(data);
            byte[] finalData = new byte[encryptedBytes.length + ivBytes.length];
            System.arraycopy(encryptedBytes, 0, finalData, 0, encryptedBytes.length);
            System.arraycopy(ivBytes, 0, finalData, encryptedBytes.length, ivBytes.length);
            return finalData;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException |
                InvalidKeyException | BadPaddingException |
                IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            throw new CryptoException("Encryption failed", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            int blockSize = cipher.getBlockSize();
            byte[] ivBytes = new byte[blockSize];
            System.arraycopy(data, data.length - ivBytes.length, ivBytes, 0, ivBytes.length);
            final IvParameterSpec iv = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            return cipher.doFinal(data, 0, data.length - ivBytes.length);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException |
                InvalidKeyException | BadPaddingException |
                IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            throw new CryptoException("Encryption failed", e);
        }
    }
}
