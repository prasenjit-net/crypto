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
import java.security.*;
import java.util.Base64;

/**
 * Created by prase on 11-06-2017.
 *
 * @author prasenjit
 * @version $Id: $Id
 */
public class AbstractSymmetricEncryptor implements TextEncryptor {
    private final String algorithm;
    private final SecretKey secretKey;
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * <p>Constructor for AbstractSymmetricEncryptor.</p>
     *
     * @param key       a {@link javax.crypto.SecretKey} object.
     * @param algorithm a {@link java.lang.String} object.
     */
    public AbstractSymmetricEncryptor(SecretKey key, String algorithm) {
        this.secretKey = key;
        this.algorithm = algorithm;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] encrypt(byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            int blockSize = cipher.getBlockSize();
            byte[] ivBytes = new byte[blockSize];
            secureRandom.nextBytes(ivBytes);
            final IvParameterSpec iv = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
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

    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] decrypt(byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            int blockSize = cipher.getBlockSize();
            byte[] ivBytes = new byte[blockSize];
            System.arraycopy(data, data.length - ivBytes.length, ivBytes, 0, ivBytes.length);
            final IvParameterSpec iv = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
            return cipher.doFinal(data, 0, data.length - ivBytes.length);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException |
                InvalidKeyException | BadPaddingException |
                IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            throw new CryptoException("Encryption failed", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String wrapKey(Key key) {
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            int blockSize = cipher.getBlockSize();
            byte[] ivBytes = new byte[blockSize];
            secureRandom.nextBytes(ivBytes);
            final IvParameterSpec iv = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.WRAP_MODE, secretKey, iv);
            byte[] encryptedBytes = cipher.wrap(key);
            byte[] finalData = new byte[encryptedBytes.length + ivBytes.length];
            System.arraycopy(encryptedBytes, 0, finalData, 0, encryptedBytes.length);
            System.arraycopy(ivBytes, 0, finalData, encryptedBytes.length, ivBytes.length);
            return Base64.getEncoder().encodeToString(finalData);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException |
                InvalidKeyException |
                IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            throw new CryptoException("Wrap failed", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Key unwrapKey(String encryptedKey, String algorithm, int type) {
        try {
            byte[] data = Base64.getDecoder().decode(encryptedKey);
            Cipher cipher = Cipher.getInstance(this.algorithm);
            int blockSize = cipher.getBlockSize();
            byte[] ivBytes = new byte[blockSize];
            System.arraycopy(data, data.length - ivBytes.length, ivBytes, 0, ivBytes.length);
            final IvParameterSpec iv = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.UNWRAP_MODE, secretKey, iv);
            byte[] encryptedBytes = new byte[data.length - blockSize];
            System.arraycopy(data, 0, encryptedBytes, 0, encryptedBytes.length);
            return cipher.unwrap(encryptedBytes, algorithm, type);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException |
                InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new CryptoException("Unwrap failed", e);
        }
    }
}
