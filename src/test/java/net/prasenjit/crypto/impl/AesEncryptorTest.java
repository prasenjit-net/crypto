/*
 *    Copyright 2017 Prasenjit Purohit
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package net.prasenjit.crypto.impl;

import net.prasenjit.crypto.TextEncryptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.security.Key;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created by prase on 11-06-2017.
 */
public class AesEncryptorTest {

    private SecretKey secretKey;

    @BeforeEach
    public void setUp() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        secretKey = generator.generateKey();
    }

    @Test
    public void encrypt() throws Exception {
        TextEncryptor encryptor = new AesEncryptor(secretKey);

        String data = "Hello World!";

        String encrypted = encryptor.encrypt(data);
        String decrypted = encryptor.decrypt(encrypted);

        assertEquals(data, decrypted);
    }

    @Test
    public void wrap() throws Exception {
        TextEncryptor encryptor = new AesEncryptor(secretKey);

        String encrypted = encryptor.wrapKey(secretKey);
        Key output = encryptor.unwrapKey(encrypted, "AES", Cipher.SECRET_KEY);

        assertEquals(secretKey.getAlgorithm(), output.getAlgorithm());
        assertTrue(Arrays.equals(secretKey.getEncoded(), output.getEncoded()));
    }

}