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
 * This interface is the base interface for all encryption feature. Created on 06-06-2017.
 *
 * @author prasenjit
 * @version $Id: $Id
 */
public interface Encryptor {
    /**
     * <p>Encrypt the provided byte array.</p>
     *
     * @param data an array of {@link byte} data to be encrypted.
     * @return an array of {@link byte} encrypted.
     */
    byte[] encrypt(byte[] data);

    /**
     * <p>Decrypt the provided byte array.</p>
     *
     * @param data an array of {@link byte}, data to be decrypted.
     * @return an array of {@link byte} decrypted.
     */
    byte[] decrypt(byte[] data);
}
