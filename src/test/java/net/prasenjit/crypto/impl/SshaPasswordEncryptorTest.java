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

import net.prasenjit.crypto.PasswordEncryptor;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Created by prase on 11-06-2017.
 */
public class SshaPasswordEncryptorTest {
    @Test
    public void encrypt() throws Exception {
        PasswordEncryptor encryptor = new SshaPasswordEncryptor();
        String plainPassword = "plain password";
        String encrypted = encryptor.encrypt(plainPassword);

        assertTrue(encryptor.testMatch(plainPassword, encrypted));
        assertFalse(encryptor.testMatch(plainPassword + "1", encrypted));
    }

}