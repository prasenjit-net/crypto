package net.prasenjit.crypto.core.impl;

import net.prasenjit.crypto.core.TextEncryptor;
import net.prasenjit.crypto.core.exception.CryptoException;

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
    private SecureRandom secureRandom = new SecureRandom();

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
            byte[] finalData = cipher.doFinal(data, 0, data.length - ivBytes.length);
            return finalData;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException |
                InvalidKeyException | BadPaddingException |
                IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            throw new CryptoException("Encryption failed", e);
        }
    }
}
