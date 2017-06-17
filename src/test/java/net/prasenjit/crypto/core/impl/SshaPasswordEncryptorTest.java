package net.prasenjit.crypto.core.impl;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Created by prase on 11-06-2017.
 */
public class SshaPasswordEncryptorTest {
    @Test
    public void encrypt() throws Exception {
        SshaPasswordEncryptor encryptor = new SshaPasswordEncryptor();
        String plainPassword = "plain password";
        String encrypted = encryptor.encrypt(plainPassword);

        assertTrue(encryptor.testMatch(plainPassword, encrypted));
        assertFalse(encryptor.testMatch(plainPassword + "1", encrypted));
    }

}