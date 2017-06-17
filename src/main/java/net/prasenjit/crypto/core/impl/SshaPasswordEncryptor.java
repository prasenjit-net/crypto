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
