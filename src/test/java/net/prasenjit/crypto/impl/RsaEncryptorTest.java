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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created by prase on 10-06-2017.
 */
public class RsaEncryptorTest {

    private KeyPair keyPair;

    @BeforeEach
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

}