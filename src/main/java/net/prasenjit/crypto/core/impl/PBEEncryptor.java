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
    private final char[] password;
    private final SecretKey secretKey;

    public PBEEncryptor(final char[] password) {
        this.password = password;
        try {
            PBEKeySpec spec = new PBEKeySpec(password);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(ALGORITHM);
            secretKey = secretKeyFactory.generateSecret(spec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new CryptoException("Key generation failed", e);
        }
    }

    @Override
    public byte[] process(byte[] data, int mode) {
        PBEKeySpec spec;
        byte[] salt = new byte[8];
        byte[] encripted = null;
        if (mode == Cipher.ENCRYPT_MODE) {
            secureRandom.nextBytes(salt);
        } else if (mode == Cipher.DECRYPT_MODE) {
            System.arraycopy(data, data.length - salt.length, salt, 0, salt.length);
            encripted = new byte[data.length - salt.length];
            System.arraycopy(data, 0, encripted, 0, data.length - salt.length);
        } else {
            throw new CryptoException("Operation mode not supported");
        }
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, 19);
            cipher.init(mode, secretKey, paramSpec);

            if (mode == Cipher.ENCRYPT_MODE) {
                encripted = cipher.doFinal(data);
                byte[] encFinal = new byte[encripted.length + salt.length];
                System.arraycopy(encripted, 0, encFinal, 0, encripted.length);
                System.arraycopy(salt, 0, encFinal, encripted.length, salt.length);
                return encFinal;
            } else {
                return cipher.doFinal(encripted);
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidAlgorithmParameterException | InvalidKeyException | BadPaddingException |
                IllegalBlockSizeException e) {
            throw new CryptoException("Encryption failed", e);
        }
    }
}
