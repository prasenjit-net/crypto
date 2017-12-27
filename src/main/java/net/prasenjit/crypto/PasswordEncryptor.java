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

package net.prasenjit.crypto;

/**
 * A digester, which digest password to store in DB. And also it perform matching of password. Created on 11-06-2017.
 *
 * @author prasenjit
 * @version $Id: $Id
 */
public interface PasswordEncryptor {
    /**
     * <p>Digest a plain text password.</p>
     *
     * @param plainPassword a {@link java.lang.String} password to digest.
     * @return a {@link java.lang.String} digested password string.
     */
    String encrypt(String plainPassword);

    /**
     * <p>Match a plain password with digested password for equality.</p>
     *
     * @param plainPassword a {@link java.lang.String} as clear text password.
     * @param encryptedPassword a {@link java.lang.String} as digested password.
     * @return a boolean true if it is a match, false otherwise.
     */
    boolean testMatch(String plainPassword, String encryptedPassword);
}
