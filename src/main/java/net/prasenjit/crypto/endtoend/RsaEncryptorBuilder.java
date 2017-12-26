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

import net.prasenjit.crypto.TextEncryptor;
import net.prasenjit.crypto.exception.CryptoException;
import net.prasenjit.crypto.impl.RsaEncryptor;
import net.prasenjit.crypto.store.CryptoKeyFactory;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

/**
 * Created by prase on 10-06-2017.
 */
public class RsaEncryptorBuilder {

    public static TextEncryptor client(PublicKey publicKey) {
        return new RsaEncryptor(publicKey);
    }

    public static TextEncryptor client(BigInteger modulus, BigInteger publicExponent) {
        try {
            RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, publicExponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(spec);
            return client(publicKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new CryptoException("Failed to re-construct RSA public key", e);
        }
    }

    public static TextEncryptor client(CryptoKeyFactory keyFactory, String alias) {
        return client(keyFactory.getPublicKey(alias));
    }

    public static TextEncryptor server(PrivateKey privateKey) {
        return new RsaEncryptor(privateKey);
    }

    public static TextEncryptor server(CryptoKeyFactory keyFactory, String alias, char[] password) {
        return new RsaEncryptor(keyFactory.getPrivateKey(alias, password));
    }
}