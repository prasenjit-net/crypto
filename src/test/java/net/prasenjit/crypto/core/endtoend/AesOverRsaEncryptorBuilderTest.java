package net.prasenjit.crypto.core.endtoend;

import net.prasenjit.crypto.core.E2eEncryptor;
import net.prasenjit.crypto.core.impl.AesOverRsaEncryptor;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.Assert.*;

/**
 * Created by prase on 17-06-2017.
 */
public class AesOverRsaEncryptorBuilderTest {
    @Test
    public void client() throws Exception {
        String data = "Hello World!";
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        E2eEncryptor client = AesOverRsaEncryptorBuilder.client(keyPair.getPublic());
        E2eEncryptor server = AesOverRsaEncryptorBuilder.server(keyPair.getPrivate(), client.getEncryptedKey());

        String result = server.decrypt(client.encrypt(data));
        assertEquals(data, result);

        result = client.decrypt(server.encrypt(data));
        assertEquals(data, result);
    }

}