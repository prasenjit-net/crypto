package net.prasenjit.crypto.core.impl;

import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.Assert.*;

/**
 * Created by prase on 17-06-2017.
 */
public class RsaSignerVerifierTest {
    @Test
    public void sign() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        RsaSignerVerifier signerVerifier = new RsaSignerVerifier(keyPair.getPublic(), keyPair.getPrivate());
        String data = "Hello World!";
        String sign = signerVerifier.sign(data);
        assertTrue(signerVerifier.verify(data, sign));
    }

}