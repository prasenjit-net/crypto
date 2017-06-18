package net.prasenjit.crypto.core.impl;

import net.prasenjit.crypto.core.E2eEncryptor;
import net.prasenjit.crypto.core.exception.CryptoException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

/**
 * Created by prase on 17-06-2017.
 */
public class AesOverRsaEncryptor implements E2eEncryptor {
    private final SecretKey secretKey;
    private final AesEncryptor aesEncryptor;
    private final RsaEncryptor rsaEncryptor;
    private boolean serverMode = true;

    public AesOverRsaEncryptor(RsaEncryptor rsaEncryptor) {
        this.rsaEncryptor = rsaEncryptor;
        this.serverMode = false;
        try {
            secretKey = KeyGenerator.getInstance("AES").generateKey();
            this.aesEncryptor = new AesEncryptor(secretKey);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Failed to generate AES key");
        }
    }

    public AesOverRsaEncryptor(RsaEncryptor rsaEncryptor, String encodedAesKey) {
        this.rsaEncryptor = rsaEncryptor;
        secretKey = rsaEncryptor.unwrapKey(encodedAesKey);
        this.aesEncryptor = new AesEncryptor(secretKey);
    }

    @Override
    public String getEncryptedKey() {
        if (serverMode) {
            throw new CryptoException("Unsupported operation for E2E server");
        }
        return this.rsaEncryptor.wrapKey(secretKey);
    }

    @Override
    public byte[] encrypt(byte[] data) {
        return this.aesEncryptor.encrypt(data);
    }

    @Override
    public byte[] decrypt(byte[] data) {
        return this.aesEncryptor.decrypt(data);
    }
}
