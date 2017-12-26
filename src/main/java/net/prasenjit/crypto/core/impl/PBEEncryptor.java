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

package net.prasenjit.crypto.core.impl;

import net.prasenjit.crypto.core.TextEncryptor;
import net.prasenjit.crypto.core.exception.CryptoException;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

/**
 * Created by prase on 06-06-2017.
 */
public class PBEEncryptor implements TextEncryptor {

    private static final String ALGORITHM = "PBEWithMD5AndDES";
    private final SecureRandom secureRandom = new SecureRandom();
    private final SecretKey secretKey;

    public PBEEncryptor(final char[] password) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(ALGORITHM);
            secretKey = secretKeyFactory.generateSecret(spec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new CryptoException("Key generation failed", e);
        }
    }

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
}
