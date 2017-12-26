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

package net.prasenjit.crypto.endtoend;

import net.prasenjit.crypto.E2eEncryptor;
import net.prasenjit.crypto.impl.AesOverRsaEncryptor;
import net.prasenjit.crypto.impl.RsaEncryptor;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Created by prase on 17-06-2017.
 */
public class AesOverRsaEncryptorBuilder {
    public static E2eEncryptor client(PublicKey publicKey) {
        RsaEncryptor rsaEncryptor = new RsaEncryptor(publicKey);
        return new AesOverRsaEncryptor(rsaEncryptor);
    }

    public static E2eEncryptor server(PrivateKey privateKey, String encodedKey) {
        RsaEncryptor rsaEncryptor = new RsaEncryptor(privateKey);
        return new AesOverRsaEncryptor(rsaEncryptor, encodedKey);
    }
}
