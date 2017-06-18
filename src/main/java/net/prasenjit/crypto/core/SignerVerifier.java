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

package net.prasenjit.crypto.core;


import java.util.Base64;

/**
 * Created by prase on 17-06-2017.
 */
public interface SignerVerifier {
    byte[] sign(byte[] data);

    default String sign(String data) {
        byte[] encryptedData = sign(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    boolean verify(byte[] data, byte[] signature);

    default boolean verify(String data, String signature) {
        byte[] sign = Base64.getDecoder().decode(signature);
        return verify(data.getBytes(), sign);
    }
}
