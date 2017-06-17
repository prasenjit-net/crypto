package net.prasenjit.crypto.core.impl;

import java.security.Key;

/**
 * Created by prase on 11-06-2017.
 */
public class DsaEncryptor extends AbstractAsymmetricEncryptor {
    protected DsaEncryptor(Key key) {
        super(key, "DSA");
    }
}
