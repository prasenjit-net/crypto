package net.prasenjit.crypto.core.impl;

import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.Assert.assertEquals;

/**
 * Created by prase on 10-06-2017.
 */
public class RsaEncryptorTest {

    private KeyPair keyPair;

    @Before
    public void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        keyPair = generator.generateKeyPair();
    }

    @Test
    public void encrypt() throws Exception {
        RsaEncryptor encryptor = new RsaEncryptor(keyPair.getPublic());
        RsaEncryptor decryptor = new RsaEncryptor(keyPair.getPrivate());

        String data = "Hello World!";

        String encrypted = encryptor.encrypt(data);
        String decrypted = decryptor.decrypt(encrypted);

        assertEquals(data, decrypted);
    }

    @Test
    public void decrypt() throws Exception {
    }

}