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


import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * This interface is used to encrypt text data, considering the encoding. Created on 06-06-2017.
 *
 * @author prasenjit
 * @version $Id: $Id
 */
public interface TextEncryptor extends Encryptor, KeyEncryptor {
    /**
     * <p>Encrypt a text with default <b>utf-8</b> charset.</p>
     *
     * @param data a {@link java.lang.String} to be encrypted.
     * @return a {@link java.lang.String} Base64 encoded encrypted text.
     */
    default String encrypt(String data) {
        return encrypt(data, StandardCharsets.UTF_8);
    }

    /**
     * <p>Decrypt a text with default <b>utf-8</b> charset.</p>
     *
     * @param data a {@link java.lang.String} encrypted and Base64 encoded.
     * @return a {@link java.lang.String} as decrypted text.
     */
    default String decrypt(String data) {
        return decrypt(data, StandardCharsets.UTF_8);
    }

    /**
     * <p>Encrypt a text with provided charset.</p>
     *
     * @param data a {@link java.lang.String} to be encrypted.
     * @param charset a {@link java.nio.charset.Charset} to convert to byte array.
     * @return a {@link java.lang.String} Base64 encoded encrypted text.
     * @since 1.1
     */
    default String encrypt(String data, Charset charset){
        byte[] encryptedData = encrypt(data.getBytes(charset));
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    /**
     * <p>Decrypt a text with provided charset.</p>
     *
     * @param data a {@link java.lang.String} encrypted and Base64 encoded.
     * @param charset a {@link java.nio.charset.Charset} to construct text.
     * @return a {@link java.lang.String} as decrypted text.
     * @since 1.1
     */
    default String decrypt(String data, Charset charset){
        byte[] encryptedData = Base64.getDecoder().decode(data);
        byte[] decryptedData = decrypt(encryptedData);
        return new String(decryptedData, charset);
    }
}
