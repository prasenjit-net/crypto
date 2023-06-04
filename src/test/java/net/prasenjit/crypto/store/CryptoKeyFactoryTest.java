/*
 *    Copyright 2023 Prasenjit Purohit
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

package net.prasenjit.crypto.store;

import net.prasenjit.crypto.exception.CryptoException;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.net.URL;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CryptoKeyFactoryTest {

    @Test
    void builder() {
        URL resource = getClass().getResource("/advanced.jceks");
        CryptoKeyFactory keyFactory = CryptoKeyFactory.builder()
                .location(resource)
                .type("JCEKS")
                .password("advanced")
                .build();
        assertNotNull(keyFactory);
        KeyPair test = keyFactory.getKeyPair("test", "test".toCharArray());
        assertNotNull(test);
        PrivateKey test1 = keyFactory.getPrivateKey("test", "test".toCharArray());
        assertNotNull(test1);
        PublicKey test2 = keyFactory.getPublicKey("test");
        assertNotNull(test2);
        Certificate cert = keyFactory.getCertificate("test");
        assertNotNull(cert);
        SecretKey secretKey = keyFactory.getSecretKey("aes", "aes".toCharArray());
        assertNotNull(secretKey);
    }

    @Test
    void builderLocationStr() {
        URL resource = getClass().getResource("/test.jks");
        assert resource != null;
        CryptoKeyFactory keyFactory = CryptoKeyFactory.builder()
                .locationStr(resource.toString())
                .password("test")
                .build();
        assertNotNull(keyFactory);
        KeyPair test = keyFactory.getKeyPair("test", "test".toCharArray());
        assertNotNull(test);
    }

    @Test
    void builderWithProviderName() {
        URL resource = getClass().getResource("/test.jks");
        assert resource != null;
        CryptoKeyFactory keyFactory = CryptoKeyFactory.builder()
                .locationStr(resource.toString())
                .providerName("SUN")
                .password("test")
                .build();
        assertNotNull(keyFactory);
        KeyPair test = keyFactory.getKeyPair("test", "test".toCharArray());
        assertNotNull(test);
    }

    @Test
    void builderWithType() {
        URL resource = getClass().getResource("/test.jks");
        assert resource != null;
        CryptoKeyFactory keyFactory = CryptoKeyFactory.builder()
                .locationStr(resource.toString())
                .type("JKS")
                .password("test")
                .build();
        assertNotNull(keyFactory);
        KeyPair test = keyFactory.getKeyPair("test", "test".toCharArray());
        assertNotNull(test);
    }

    @Test
    void builderWithProvider() {
        URL resource = getClass().getResource("/test.jks");
        assert resource != null;
        CryptoKeyFactory keyFactory = CryptoKeyFactory.builder()
                .locationStr(resource.toString())
                .type("JKS")
                .provider(Security.getProvider("SUN"))
                .password("test")
                .build();
        assertNotNull(keyFactory);
        KeyPair test = keyFactory.getKeyPair("test", "test".toCharArray());
        assertNotNull(test);
    }

    @Test
    void builderFailedInstantiate() {
        URL resource = getClass().getResource("/test.jks");
        assert resource != null;
        CryptoKeyFactory keyFactory = CryptoKeyFactory.builder()
                .locationStr(resource.toString())
                .type("JKS1")
                .provider(Security.getProvider("SUN"))
                .password("test")
                .build();
        assertNotNull(keyFactory);
        assertThrows(CryptoException.class, () -> keyFactory.getKeyPair("test", "test".toCharArray()), "Failed to instantiate key store");
    }

    @Test
    void builderNoCertLocation() {
        CryptoKeyFactory keyFactory = CryptoKeyFactory.builder()
                .type("JKS")
                .build();
        assertNotNull(keyFactory);
        assertThrows(CryptoException.class, () -> keyFactory.getKeyPair("test", "test".toCharArray()), "location in null");
    }

    @Test
    void builderInvalidCertLocation() {
        CryptoKeyFactory keyFactory = CryptoKeyFactory.builder()
                .locationStr("invalid")
                .type("JKS")
                .build();
        assertNotNull(keyFactory);
        assertThrows(CryptoException.class, () -> keyFactory.getKeyPair("test", "test".toCharArray()), "malformed locationStr");
    }

    @Test
    void builderInvalidJKSFile() {
        URL resource = getClass().getResource("/invalid_jks.txt");
        assert resource != null;
        CryptoKeyFactory keyFactory = CryptoKeyFactory.builder()
                .location(resource)
                .type("JKS")
                .build();
        assertNotNull(keyFactory);
        assertThrows(CryptoException.class, () -> keyFactory.getKeyPair("test", "test".toCharArray()), "malformed locationStr");
    }
}