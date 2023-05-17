/*
 *    Copyright 2020 Prasenjit Purohit
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

import static org.junit.jupiter.api.Assertions.*;

/**
 * <p>PBKDF2PasswordEncryptorTest class.</p>
 *
 * @author prasenjit
 * @version $Id: $Id
 * @since 1.5
 */
public class PBKDF2PasswordEncryptorTest {

    /**
     * <p>testMatch.</p>
     */
    @Test
    public void testMatch() {
        String plainPassword = "some string password";
        PBKDF2PasswordEncryptor encryptor = new PBKDF2PasswordEncryptor();
        final String encrypted = encryptor.encrypt(plainPassword);

        assertTrue(encryptor.testMatch(plainPassword, encrypted));
        assertFalse(encryptor.testMatch(plainPassword + "1", encrypted));
    }
}
