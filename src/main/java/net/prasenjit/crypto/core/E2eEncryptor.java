package net.prasenjit.crypto.core;

/**
 * Created by prase on 17-06-2017.
 */
public interface E2eEncryptor extends TextEncryptor {
    String getEncryptedKey();
}
