/*
 *    Copyright 2020 Prasenjit Purohit
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

import net.prasenjit.crypto.PasswordEncryptor;
import net.prasenjit.crypto.exception.CryptoException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * <p>PBKDF2PasswordEncryptor class.</p>
 *
 * @author prasenjit
 * @version $Id: $Id
 */
public class PBKDF2PasswordEncryptor implements PasswordEncryptor {
    private final SecureRandom secureRandom;
    private int saltSize = 16;
    private int cost = 65536;

    /**
     * <p>Constructor for PBKDF2PasswordEncryptor.</p>
     */
    public PBKDF2PasswordEncryptor() {
        this.secureRandom = new SecureRandom();
    }

    /**
     * <p>Constructor for PBKDF2PasswordEncryptor.</p>
     *
     * @param random a {@link java.security.SecureRandom} object.
     */
    public PBKDF2PasswordEncryptor(SecureRandom random) {
        this.secureRandom = random;
    }

    /** {@inheritDoc} */
    @Override
    public String encrypt(String plainPassword) {
        try {
            byte[] salt = new byte[this.saltSize];
            this.secureRandom.nextBytes(salt);
            KeySpec spec = new PBEKeySpec(plainPassword.toCharArray(), salt, this.cost, 128);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            final byte[] encoded = factory.generateSecret(spec).getEncoded();
            byte[] output = new byte[this.saltSize + encoded.length];
            System.arraycopy(encoded, 0, output, 0, encoded.length);
            System.arraycopy(salt, 0, output, encoded.length, salt.length);
            return Base64.getEncoder().encodeToString(output);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CryptoException("Failed to digest password", e);
        }
    }

    /** {@inheritDoc} */
    @Override
    public boolean testMatch(String plainPassword, String encryptedPassword) {
        byte[] data = Base64.getDecoder().decode(encryptedPassword);
        byte[] salt = new byte[this.saltSize];
        byte[] digested = new byte[data.length - salt.length];
        System.arraycopy(data, data.length - salt.length, salt, 0, salt.length);
        System.arraycopy(data, 0, digested, 0, data.length - salt.length);

        KeySpec spec = new PBEKeySpec(plainPassword.toCharArray(), salt, this.cost, 128);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            final byte[] encoded = factory.generateSecret(spec).getEncoded();
            return Arrays.equals(digested, encoded);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CryptoException("Failed to digest password", e);
        }
    }

    /**
     * <p>Getter for the field <code>cost</code>.</p>
     *
     * @return a int.
     */
    public int getCost() {
        return cost;
    }

    /**
     * <p>Setter for the field <code>cost</code>.</p>
     *
     * @param cost a int.
     */
    public void setCost(int cost) {
        this.cost = cost;
    }

    /**
     * <p>Getter for the field <code>saltSize</code>.</p>
     *
     * @return a int.
     */
    public int getSaltSize() {
        return saltSize;
    }

    /**
     * <p>Setter for the field <code>saltSize</code>.</p>
     *
     * @param saltSize a int.
     */
    public void setSaltSize(int saltSize) {
        this.saltSize = saltSize;
    }
}
