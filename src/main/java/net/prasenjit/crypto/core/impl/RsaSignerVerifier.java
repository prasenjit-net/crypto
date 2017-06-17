package net.prasenjit.crypto.core.impl;

import net.prasenjit.crypto.core.SignerVerifier;
import net.prasenjit.crypto.core.exception.CryptoException;

import java.security.*;

/**
 * Created by prase on 17-06-2017.
 */
public class RsaSignerVerifier implements SignerVerifier {

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
                Signature signature = Signature.getInstance("SHA1WithRSA");
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
                Signature signature = Signature.getInstance("SHA1WithRSA");
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
