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
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created by prase on 17-06-2017.
 *
 * @author prasenjit
 * @version $Id: $Id
 * @since 1.5
 */
public class RsaEncryptorBuilderTest {
    /**
     * <p>client.</p>
     *
     * @throws java.lang.Exception if any.
     */
    @Test
    public void client() throws Exception {
        String data = "Hello World!";
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        TextEncryptor client = RsaEncryptorBuilder.client(keyPair.getPublic());
        TextEncryptor server = RsaEncryptorBuilder.server(keyPair.getPrivate());

        String output = server.decrypt(client.encrypt(data));

        assertEquals(data, output);
    }
    /**
     * <p>client.</p>
     *
     * @throws java.lang.Exception if any.
     */
    @Test
    public void clientWithModExpo() throws Exception {
        String data = "Hello World!";
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        RSAPublicKey rsaPublic = (RSAPublicKey) keyPair.getPublic();
        TextEncryptor client = RsaEncryptorBuilder.client(rsaPublic.getModulus(), rsaPublic.getPublicExponent());
        TextEncryptor server = RsaEncryptorBuilder.server(keyPair.getPrivate());

        String output = server.decrypt(client.encrypt(data));

        assertEquals(data, output);
    }

    @Test
    void server() {
    }

    @Test
    void testServer() {
    }
}
