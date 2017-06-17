package net.prasenjit.crypto.core.impl;

import net.prasenjit.crypto.core.TextEncryptor;
import net.prasenjit.crypto.core.exception.CryptoException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

/**
 * Created by prase on 11-06-2017.
 */
public abstract class AbstractAsymmetricEncryptor implements TextEncryptor {
    protected final Key key;
    protected final String algorithm;

    protected AbstractAsymmetricEncryptor(Key key, String algorithm) {
        this.key = key;
        this.algorithm = algorithm;
    }

    @Override
    public byte[] process(byte[] data, int mode) {
        if (key instanceof PublicKey && (mode != Cipher.ENCRYPT_MODE)) {
            throw new CryptoException("PublicKey should not be used for decryption");
        } else if (key instanceof PrivateKey && (mode != Cipher.DECRYPT_MODE)) {
            throw new CryptoException("PrivateKey should not be used for encryption");
        }
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(mode, key);

            return cipher.doFinal(data);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException |
                InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            throw new CryptoException("Encryption failed", e);
        }
    }
}
