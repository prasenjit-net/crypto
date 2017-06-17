package net.prasenjit.crypto.core.impl;

import org.junit.Before;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import static org.junit.Assert.assertEquals;

/**
 * Created by prase on 11-06-2017.
 */
public class AesEncryptorTest {

    private SecretKey secretKey;

    @Before
    public void setUp() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        secretKey = generator.generateKey();
    }

    @Test
    public void encrypt() throws Exception {
        AesEncryptor encryptor = new AesEncryptor(secretKey);

        String data = "Hello World!";

        String encrypted = encryptor.encrypt(data);
        String decrypted = encryptor.decrypt(encrypted);

        assertEquals(data, decrypted);
    }

}