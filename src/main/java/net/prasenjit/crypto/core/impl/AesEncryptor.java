package net.prasenjit.crypto.core.impl;

import javax.crypto.SecretKey;

/**
 * Created by prase on 11-06-2017.
 */
public class AesEncryptor extends AbstractSymmetricEncryptor {
    public AesEncryptor(SecretKey key) {
        super(key, "AES/CBC/PKCS5Padding");
    }
}
