package net.prasenjit.crypto.core.impl;

import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.Assert.*;

/**
 * Created by prase on 11-06-2017.
 */
public class DsaEncryptorTest {
    private KeyPair keyPair;

    @Before
    public void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
        generator.initialize(1024);
        keyPair = generator.generateKeyPair();
    }

    @Test
    public void encrypt() throws Exception {
        DsaEncryptor encryptor = new DsaEncryptor(keyPair.getPublic());
        DsaEncryptor decryptor = new DsaEncryptor(keyPair.getPrivate());

        String data = "Hello World!";

        String encrypted = encryptor.encrypt(data);
        String decrypted = decryptor.decrypt(encrypted);

        assertEquals(data, decrypted);
    }
}