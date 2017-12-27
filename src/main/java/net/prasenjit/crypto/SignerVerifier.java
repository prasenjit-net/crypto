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
 * An interface to perform data signing and verification. Created on 17-06-2017.
 *
 * @author prasenjit
 * @version $Id: $Id
 */
public interface SignerVerifier {
    /**
     * <p>Sign a data.</p>
     *
     * @param data an array of {@link byte} to be signed.
     * @return an array of {@link byte} as signature.
     */
    byte[] sign(byte[] data);

    /**
     * <p>Sign a text with default <b>utf-8</b> charset.</p>
     *
     * @param data a {@link java.lang.String} to be signed.
     * @return a {@link java.lang.String} signature Base64 encoded.
     */
    default String sign(String data) {
        return sign(data, StandardCharsets.UTF_8);
    }

    /**
     * <p>Sign a data.</p>
     *
     * @param data a {@link java.lang.String} to be signed.
     * @param charset a {@link java.nio.charset.Charset} to convert to binary.
     * @return a {@link java.lang.String} signature Base64 encoded.
     * @since 1.1
     */
    default String sign(String data, Charset charset) {
        byte[] encryptedData = sign(data.getBytes(charset));
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    /**
     * <p>Verify a signature with data.</p>
     *
     * @param data an array of {@link byte} to be verified.
     * @param signature an array of {@link byte} as signature.
     * @return a boolean true if signature matches otherwise false.
     */
    boolean verify(byte[] data, byte[] signature);

    /**
     * <p>Verify a signature with data using default <b>utf-8</b> charset.</p>
     *
     * @param data a {@link java.lang.String} to be verified.
     * @param signature a {@link java.lang.String} Base64 encoded signature.
     * @return a boolean true if signature matches otherwise false.
     */
    default boolean verify(String data, String signature) {
        return verify(data, signature, StandardCharsets.UTF_8);
    }

    /**
     * <p>Verify a signature with data using provided charset.</p>
     *
     * @param data a {@link java.lang.String} to be verified.
     * @param signature a {@link java.lang.String} Base64 encoded signature.
     * @param charset a {@link java.nio.charset.Charset} to convert to binary.
     * @return a boolean true if signature matches otherwise false.
     * @since 1.1
     */
    default boolean verify(String data, String signature, Charset charset) {
        byte[] sign = Base64.getDecoder().decode(signature);
        return verify(data.getBytes(charset), sign);
    }
}
