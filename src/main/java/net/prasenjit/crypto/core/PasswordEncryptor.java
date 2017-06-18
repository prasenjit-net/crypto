package net.prasenjit.crypto.core;

/**
 * Created by prase on 11-06-2017.
 */
public interface PasswordEncryptor {
    String encrypt(String plainPassword);

    boolean testMatch(String plainPassword, String encryptedPassword);
}
