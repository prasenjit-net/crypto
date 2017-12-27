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

package net.prasenjit.crypto.impl;

import net.prasenjit.crypto.SignerVerifier;
import net.prasenjit.crypto.exception.CryptoException;

import java.security.*;

/**
 * Created by prase on 17-06-2017.
 *
 * @author prasenjit
 * @version $Id: $Id
 */
public class RsaSignerVerifier implements SignerVerifier {

    /** Constant <code>ALGORITHM="SHA1WithRSA"</code> */
    public static final String ALGORITHM = "SHA1WithRSA";
    private final PublicKey publicKey;
    private final PrivateKey privateKey;

    /**
     * <p>Constructor for RsaSignerVerifier.</p>
     *
     * @param publicKey a {@link java.security.PublicKey} object.
     * @param privateKey a {@link java.security.PrivateKey} object.
     */
    public RsaSignerVerifier(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    /**
     * <p>Constructor for RsaSignerVerifier.</p>
     *
     * @param publicKey a {@link java.security.PublicKey} object.
     */
    public RsaSignerVerifier(PublicKey publicKey) {
        this.publicKey = publicKey;
        this.privateKey = null;
    }

    /**
     * <p>Constructor for RsaSignerVerifier.</p>
     *
     * @param privateKey a {@link java.security.PrivateKey} object.
     */
    public RsaSignerVerifier(PrivateKey privateKey) {
        this.publicKey = null;
        this.privateKey = privateKey;
    }

    /** {@inheritDoc} */
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

    /** {@inheritDoc} */
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
