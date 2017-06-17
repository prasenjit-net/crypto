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
    private final int ivLength;
    private SecureRandom secureRandom = new SecureRandom();
    private final SecretKey key;

    public AbstractSymmetricEncryptor(SecretKey key, String algorithm, int ivLength) {
        this.key = key;
        this.algorithm = algorithm;
        this.ivLength = ivLength;
    }

    @Override
    public byte[] process(byte[] data, int mode) {
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            byte[] ivBytes = new byte[ivLength];
            if (mode == Cipher.ENCRYPT_MODE) {
                secureRandom.nextBytes(ivBytes);
                final IvParameterSpec iv = new IvParameterSpec(ivBytes);
                cipher.init(mode, key, iv);
                byte[] encryptedBytes = cipher.doFinal(data);
                byte[] finalData = new byte[encryptedBytes.length + ivBytes.length];
                System.arraycopy(encryptedBytes, 0, finalData, 0, encryptedBytes.length);
                System.arraycopy(ivBytes, 0, finalData, encryptedBytes.length, ivBytes.length);
                return finalData;
            }else if (mode == Cipher.DECRYPT_MODE){
                System.arraycopy(data, data.length - ivBytes.length, ivBytes, 0, ivBytes.length);
                final IvParameterSpec iv = new IvParameterSpec(ivBytes);
                cipher.init(mode, key, iv);
                byte[] finalData = cipher.doFinal(data, 0, data.length - ivBytes.length);
                return finalData;
            } else {
                throw new CryptoException("Processing mode not supported");
            }
        } catch (NoSuchPaddingException | NoSuchAlgorithmException |
                InvalidKeyException | BadPaddingException |
                IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            throw new CryptoException("Encryption failed", e);
        }
    }
}
