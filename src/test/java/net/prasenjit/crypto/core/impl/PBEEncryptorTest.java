package net.prasenjit.crypto.core.impl;

import org.jasypt.encryption.pbe.PBEStringEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Created by prase on 13-06-2017.
 */
public class PBEEncryptorTest {
    @Test
    public void process() throws Exception {
        String data = "My precious data";
        PBEEncryptor encryptor = new PBEEncryptor("password".toCharArray());
        String encrypt = encryptor.encrypt(data);

        String decrypt = encryptor.decrypt(encrypt);

        assertEquals(data, decrypt);
    }

    @Test
    public void jasyptTest(){
        PBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        encryptor.setPassword("password");
        String message = "Some important message";
        String encrypt = encryptor.encrypt(message);

        String decrypt = encryptor.decrypt(encrypt);

        assertEquals(message, decrypt);
    }

}