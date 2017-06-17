package net.prasenjit.crypto.core.impl;

import net.prasenjit.crypto.core.exception.CryptoException;

import java.security.Key;
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

}
