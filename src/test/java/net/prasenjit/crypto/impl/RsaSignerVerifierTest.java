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

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Created by prase on 17-06-2017.
 *
 * @author prasenjit
 * @version $Id: $Id
 * @since 1.5
 */
public class RsaSignerVerifierTest {
    /**
     * <p>sign.</p>
     *
     * @throws java.lang.Exception if any.
     */
    @Test
    public void sign() throws Exception {
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        RsaSignerVerifier signerVerifier = new RsaSignerVerifier(keyPair.getPublic(), keyPair.getPrivate());
        String data = "Hello World!";
        String sign = signerVerifier.sign(data);
        assertTrue(signerVerifier.verify(data, sign));
    }

}
