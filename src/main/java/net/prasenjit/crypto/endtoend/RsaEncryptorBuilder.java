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
 *
 * @author prasenjit
 * @version $Id: $Id
 */
public class RsaEncryptorBuilder {

    /**
     * <p>client.</p>
     *
     * @param publicKey a {@link java.security.PublicKey} object.
     * @return a {@link net.prasenjit.crypto.TextEncryptor} object.
     */
    public static TextEncryptor client(PublicKey publicKey) {
        return new RsaEncryptor(publicKey);
    }

    /**
     * <p>client.</p>
     *
     * @param modulus a {@link java.math.BigInteger} object.
     * @param publicExponent a {@link java.math.BigInteger} object.
     * @return a {@link net.prasenjit.crypto.TextEncryptor} object.
     */
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

    /**
     * <p>client.</p>
     *
     * @param keyFactory a {@link net.prasenjit.crypto.store.CryptoKeyFactory} object.
     * @param alias a {@link java.lang.String} object.
     * @return a {@link net.prasenjit.crypto.TextEncryptor} object.
     */
    public static TextEncryptor client(CryptoKeyFactory keyFactory, String alias) {
        return client(keyFactory.getPublicKey(alias));
    }

    /**
     * <p>server.</p>
     *
     * @param privateKey a {@link java.security.PrivateKey} object.
     * @return a {@link net.prasenjit.crypto.TextEncryptor} object.
     */
    public static TextEncryptor server(PrivateKey privateKey) {
        return new RsaEncryptor(privateKey);
    }

    /**
     * <p>server.</p>
     *
     * @param keyFactory a {@link net.prasenjit.crypto.store.CryptoKeyFactory} object.
     * @param alias a {@link java.lang.String} object.
     * @param password an array of {@link char} objects.
     * @return a {@link net.prasenjit.crypto.TextEncryptor} object.
     */
    public static TextEncryptor server(CryptoKeyFactory keyFactory, String alias, char[] password) {
        return new RsaEncryptor(keyFactory.getPrivateKey(alias, password));
    }
}
