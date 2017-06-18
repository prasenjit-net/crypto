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

import net.prasenjit.crypto.core.PasswordEncryptor;
import net.prasenjit.crypto.core.exception.CryptoException;
import org.apache.commons.codec.binary.Base64;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Created by prase on 11-06-2017.
 */
public class SshaPasswordEncryptor implements PasswordEncryptor {
    private SecureRandom secureRandom = new SecureRandom();

    @Override
    public String encrypt(String plainPassword) {

        byte[] salt = new byte[8];
        secureRandom.nextBytes(salt);
        byte[] data = plainPassword.getBytes();
        byte[] digest = digest(data, salt);
        byte[] output = new byte[digest.length + salt.length];
        System.arraycopy(digest, 0, output, 0, digest.length);
        System.arraycopy(salt, 0, output, digest.length, salt.length);
        return Base64.encodeBase64String(output);
    }

    @Override
    public boolean testMatch(String plainPassword, String encryptedPassword) {
        byte[] data = Base64.decodeBase64(encryptedPassword);
        byte[] salt = new byte[8];
        byte[] digested = new byte[data.length - salt.length];
        System.arraycopy(data, data.length - salt.length, salt, 0, salt.length);
        System.arraycopy(data, 0, digested, 0, data.length - salt.length);
        byte[] newData = digest(plainPassword.getBytes(), salt);
        return Arrays.equals(digested, newData);
    }

    private byte[] digest(byte[] data, byte[] salt) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(data);
            return messageDigest.digest(salt);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Failed to digest password");
        }
    }
}
