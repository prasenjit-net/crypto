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

import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.security.Key;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created by prase on 13-06-2017.
 *
 * @author prasenjit
 * @version $Id: $Id
 * @since 1.5
 */
public class PBEEncryptorTest {
    /**
     * <p>process.</p>
     *
     * @throws java.lang.Exception if any.
     */
    @Test
    public void process() throws Exception {
        String data = "My precious data";
        PBEEncryptor encryptor = new PBEEncryptor("password".toCharArray());
        String encrypt = encryptor.encrypt(data);

        String decrypt = encryptor.decrypt(encrypt);

        assertEquals(data, decrypt);
    }

    /**
     * <p>wrap.</p>
     *
     * @throws java.lang.Exception if any.
     */
    @Test
    public void wrap() throws Exception {
        SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
        PBEEncryptor encryptor = new PBEEncryptor("password".toCharArray());
        String encrypt = encryptor.wrapKey(secretKey);

        Key decrypted = encryptor.unwrapKey(encrypt, "AES", Cipher.SECRET_KEY);

        assertEquals(decrypted.getAlgorithm(), secretKey.getAlgorithm());
        assertTrue(Arrays.equals(decrypted.getEncoded(), secretKey.getEncoded()));
    }
}
