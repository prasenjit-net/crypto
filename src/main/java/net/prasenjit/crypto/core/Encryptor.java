package net.prasenjit.crypto.core;

/**
 * Created by prase on 06-06-2017.
 */
public interface Encryptor {
    byte[] encrypt(byte[] data);

    byte[] decrypt(byte[] data);
}
