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

package net.prasenjit.crypto.core.impl;

import net.prasenjit.crypto.core.SignerVerifier;
import net.prasenjit.crypto.core.exception.CryptoException;

import java.security.*;

/**
 * Created by prase on 17-06-2017.
 */
public class RsaSignerVerifier implements SignerVerifier {

    public static final String ALGORITHM = "SHA1WithRSA";
    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    public RsaSignerVerifier(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public RsaSignerVerifier(PublicKey publicKey) {
        this.publicKey = publicKey;
        this.privateKey = null;
    }

    public RsaSignerVerifier(PrivateKey privateKey) {
        this.publicKey = null;
        this.privateKey = privateKey;
    }

    @Override
    public byte[] sign(byte[] data) {
        if (privateKey != null) {
            try {
                Signature signature = Signature.getInstance(ALGORITHM);
                signature.initSign(privateKey);
                signature.update(data);
                return signature.sign();
            } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                throw new CryptoException("Signature failed", e);
            }
        }
        throw new CryptoException("Private key not found, sign not supported");
    }

    @Override
    public boolean verify(byte[] data, byte[] sign) {
        if (publicKey != null) {
            try {
                Signature signature = Signature.getInstance(ALGORITHM);
                signature.initVerify(publicKey);
                signature.update(data);
                return signature.verify(sign);
            } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                throw new CryptoException("Verification failed", e);
            }
        }
        throw new CryptoException("Public key not found, verify not supported");
    }
}
