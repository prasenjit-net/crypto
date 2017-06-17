package net.prasenjit.crypto.core.endtoend;

import net.prasenjit.crypto.core.E2eEncryptor;
import net.prasenjit.crypto.core.impl.AesOverRsaEncryptor;
import net.prasenjit.crypto.core.impl.RsaEncryptor;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Created by prase on 17-06-2017.
 */
public class AesOverRsaEncryptorBuilder {
    public static E2eEncryptor client(PublicKey publicKey) {
        RsaEncryptor rsaEncryptor = new RsaEncryptor(publicKey);
        return new AesOverRsaEncryptor(rsaEncryptor);
    }

    public static E2eEncryptor server(PrivateKey privateKey, String encodedKey) {
        RsaEncryptor rsaEncryptor = new RsaEncryptor(privateKey);
        return new AesOverRsaEncryptor(rsaEncryptor, encodedKey);
    }
}
