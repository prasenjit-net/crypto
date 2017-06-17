package net.prasenjit.crypto.core.endtoend;

import net.prasenjit.crypto.core.Encryptor;
import net.prasenjit.crypto.core.exception.CryptoException;
import net.prasenjit.crypto.core.impl.RsaEncryptor;
import net.prasenjit.crypto.core.store.CryptoKeyFactory;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

/**
 * Created by prase on 10-06-2017.
 */
public class RsaEncryptorBuilder {

    public static Encryptor client(PublicKey publicKey) {
        return new RsaEncryptor(publicKey);
    }

    public static Encryptor client(BigInteger modulus, BigInteger publicExponent) {
        try {
            RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, publicExponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(spec);
            return client(publicKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CryptoException("Failed to re-construct RSA public key", e);
        }
    }

    public static Encryptor client(CryptoKeyFactory keyFactory, String alias) {
        return client(keyFactory.getPublicKey(alias));
    }

    public static Encryptor server(PrivateKey privateKey) {
        return new RsaEncryptor(privateKey);
    }

    public static Encryptor server(CryptoKeyFactory keyFactory, String alias, char[] password) {
        return new RsaEncryptor(keyFactory.getPrivateKey(alias, password));
    }
}