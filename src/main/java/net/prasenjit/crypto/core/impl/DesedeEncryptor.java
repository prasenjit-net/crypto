package net.prasenjit.crypto.core.impl;

import javax.crypto.SecretKey;

/**
 * Created by prase on 11-06-2017.
 */
public class DesedeEncryptor extends AbstractSymmetricEncryptor {
    public DesedeEncryptor(SecretKey key) {
        super(key, "DESede/CBC/PKCS5Padding");
    }
}
