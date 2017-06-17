package net.prasenjit.crypto.core.impl;

import net.prasenjit.crypto.core.exception.CryptoException;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.*;
import java.security.interfaces.RSAKey;

/**
 * Created by prase on 10-06-2017.
 */
public class RsaEncryptor extends AbstractAsymmetricEncryptor {

    public RsaEncryptor(Key rsaKey) {
        super(rsaKey, "RSA");
        if (!(rsaKey instanceof RSAKey)) {
            throw new CryptoException("Only RSA keys are supported with RsaEncryptor");
        }
    }

    public String wrapKey(SecretKey keyToWrap) {
        if (key instanceof PrivateKey) {
            throw new CryptoException("PrivateKey should not be used for encryption");
        }
        try {
            Cipher wrapper = Cipher.getInstance(algorithm);
            wrapper.init(Cipher.WRAP_MODE, this.key);
            byte[] wrappedKey = wrapper.wrap(keyToWrap);
            return Base64.encodeBase64String(wrappedKey);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | InvalidKeyException e) {
            throw new CryptoException("Failed to wrap key", e);
        }
    }

    public SecretKey unwrapKey(String wrappedKey) {
        if (key instanceof PublicKey) {
            throw new CryptoException("PublicKey should not be used for decryption");
        }
        try {
            Cipher wrapper = Cipher.getInstance(algorithm);
            wrapper.init(Cipher.UNWRAP_MODE, this.key);
            byte[] wrappedByte = Base64.decodeBase64(wrappedKey);
            return (SecretKey) wrapper.unwrap(wrappedByte, "AES", Cipher.SECRET_KEY);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new CryptoException("Failed to wrap key", e);
        }
    }
}
