package net.prasenjit.crypto.core.endtoend;

import net.prasenjit.crypto.core.Encryptor;
import net.prasenjit.crypto.core.TextEncryptor;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.Assert.*;

/**
 * Created by prase on 17-06-2017.
 */
public class RsaEncryptorBuilderTest {
    @Test
    public void client() throws Exception {
        String data = "Hello World!";
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        TextEncryptor client = RsaEncryptorBuilder.client(keyPair.getPublic());
        TextEncryptor server = RsaEncryptorBuilder.server(keyPair.getPrivate());

        String output = server.decrypt(client.encrypt(data));

        assertEquals(data, output);
    }

}