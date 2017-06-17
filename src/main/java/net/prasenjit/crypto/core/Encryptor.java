package net.prasenjit.crypto.core;

import javax.crypto.Cipher;

/**
 * Created by prase on 06-06-2017.
 */
public interface Encryptor {
    default byte[] encrypt(byte[] data) {
        return process(data, Cipher.ENCRYPT_MODE);
    }

    default byte[] decrypt(byte[] data) {
        return process(data, Cipher.DECRYPT_MODE);
    }

    byte[] process(byte[] data, int mode);
}
