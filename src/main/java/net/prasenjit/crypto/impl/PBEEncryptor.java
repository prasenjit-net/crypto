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
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * Created by prase on 06-06-2017.
 *
 * @author prasenjit
 * @version $Id: $Id
 */
public class PBEEncryptor implements TextEncryptor {

    private static final String ALGORITHM = "PBEWithMD5AndDES";
    private final SecureRandom secureRandom = new SecureRandom();
    private final SecretKey secretKey;

    /**
     * <p>Constructor for PBEEncryptor.</p>
     *
     * @param password an array of {@link char} objects.
     */
    public PBEEncryptor(final char[] password) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(ALGORITHM);
            secretKey = secretKeyFactory.generateSecret(spec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new CryptoException("Key generation failed", e);
        }
    }

    /** {@inheritDoc} */
    @Override
    public byte[] encrypt(byte[] data) {
        byte[] salt = new byte[8];
        byte[] encripted;
        secureRandom.nextBytes(salt);
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, 19);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
            encripted = cipher.doFinal(data);
            byte[] encFinal = new byte[encripted.length + salt.length];
            System.arraycopy(encripted, 0, encFinal, 0, encripted.length);
            System.arraycopy(salt, 0, encFinal, encripted.length, salt.length);
            return encFinal;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException |
                IllegalBlockSizeException e) {
            throw new CryptoException("Encryption failed", e);
        }
    }

    /** {@inheritDoc} */
    @Override
    public byte[] decrypt(byte[] data) {
        byte[] salt = new byte[8];
        byte[] encripted;
        System.arraycopy(data, data.length - salt.length, salt, 0, salt.length);
        encripted = new byte[data.length - salt.length];
        System.arraycopy(data, 0, encripted, 0, data.length - salt.length);
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, 19);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
            return cipher.doFinal(encripted);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException |
                IllegalBlockSizeException e) {
            throw new CryptoException("Decryption failed", e);
        }
    }

    /** {@inheritDoc} */
    @Override
    public String wrapKey(Key key) {
        try {
            byte[] salt = new byte[8];
            secureRandom.nextBytes(salt);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, 19);
            cipher.init(Cipher.WRAP_MODE, secretKey, paramSpec);
            byte[] encryptedBytes = cipher.wrap(key);
            byte[] finalData = new byte[encryptedBytes.length + salt.length];
            System.arraycopy(encryptedBytes, 0, finalData, 0, encryptedBytes.length);
            System.arraycopy(salt, 0, finalData, encryptedBytes.length, salt.length);
            return Base64.getEncoder().encodeToString(finalData);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException |
                InvalidKeyException |
                IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            throw new CryptoException("Wrap failed", e);
        }
    }

    /** {@inheritDoc} */
    @Override
    public Key unwrapKey(String encryptedKey, String algorithm, int type) {
        try {
            byte[] data = Base64.getDecoder().decode(encryptedKey);
            byte[] salt = new byte[8];
            byte[] encrypted = new byte[data.length - salt.length];
            System.arraycopy(data, data.length - salt.length, salt, 0, salt.length);
            System.arraycopy(data, 0, encrypted, 0, data.length - salt.length);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, 19);
            cipher.init(Cipher.UNWRAP_MODE, secretKey, paramSpec);
            return cipher.unwrap(encrypted, algorithm, type);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException |
                InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new CryptoException("Unwrap failed", e);
        }
    }
}
