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

package net.prasenjit.crypto.store;

import net.prasenjit.crypto.exception.CryptoException;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by prase on 09-06-2017.
 *
 * @author prasenjit
 * @version $Id: $Id
 */
public class CryptoKeyFactory {
    private static final Logger log = Logger.getLogger(CryptoKeyFactory.class.getName());
    private String type = "JKS";
    private URL location;
    private final String locationStr;
    private String password = "changeit";
    private String providerName;
    private Provider provider;
    private final String providerClassName;

    private transient KeyStore keyStore;

    CryptoKeyFactory(String type, URL location, String locationStr, String password, String providerName, Provider provider, String providerClassName, KeyStore keyStore) {
        this.type = type;
        this.location = location;
        this.locationStr = locationStr;
        this.password = password;
        this.providerName = providerName;
        this.provider = provider;
        this.providerClassName = providerClassName;
        this.keyStore = keyStore;
    }

    /**
     * <p>builder.</p>
     *
     * @return a {@link net.prasenjit.crypto.store.CryptoKeyFactory.CryptoKeyFactoryBuilder} object.
     */
    public static CryptoKeyFactoryBuilder builder() {
        return new CryptoKeyFactoryBuilder();
    }

    private synchronized void initialize() {
        try {
            if (provider != null) {
                keyStore = KeyStore.getInstance(type, provider);
            } else if (providerClassName != null) {
                Provider loadedProvider = (Provider) Class.forName(providerClassName).newInstance();
                Security.addProvider(loadedProvider);
                provider = loadedProvider;
                providerName = loadedProvider.getName();
                keyStore = KeyStore.getInstance(type, provider);
            } else if (providerName != null) {
                keyStore = KeyStore.getInstance(type, providerName);
            } else {
                keyStore = KeyStore.getInstance(type);
            }
        } catch (KeyStoreException | ClassNotFoundException | IllegalAccessException |
                InstantiationException | NoSuchProviderException e) {
            throw new CryptoException("Failed to instantiate key store", e);
        }
        InputStream inputStream = null;
        try {
            if (locationStr != null) {
                location = URI.create(locationStr).toURL();
            }
            inputStream = location != null ? location.openStream() : null;
            char[] passwordChar = password != null ? password.toCharArray() : null;
            keyStore.load(inputStream, passwordChar);
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new CryptoException("Failed to load key store", e);
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    log.log(Level.WARNING, "Failed to close stream", e);
                }
            }
        }
    }

    /**
     * <p>getSecretKey.</p>
     *
     * @param alias    a {@link java.lang.String} object.
     * @param password an array of {@link char} objects.
     * @return a {@link javax.crypto.SecretKey} object.
     */
    public SecretKey getSecretKey(String alias, char[] password) {
        this.initialize();
        try {
            Key key = keyStore.getKey(alias, password);
            if (key instanceof SecretKey) {
                return (SecretKey) key;
            }
            return null;
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new CryptoException("Failed to extract secret key", e);
        }
    }

    /**
     * <p>getPrivateKey.</p>
     *
     * @param alias    a {@link java.lang.String} object.
     * @param password an array of {@link char} objects.
     * @return a {@link java.security.PrivateKey} object.
     */
    public PrivateKey getPrivateKey(String alias, char[] password) {
        this.initialize();
        try {
            Key key = keyStore.getKey(alias, password);
            if (key instanceof PrivateKey) {
                return (PrivateKey) key;
            }
            return null;
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new CryptoException("Failed to extract private key", e);
        }
    }

    /**
     * <p>getPublicKey.</p>
     *
     * @param alias a {@link java.lang.String} object.
     * @return a {@link java.security.PublicKey} object.
     */
    public PublicKey getPublicKey(String alias) {
        this.initialize();
        try {
            java.security.cert.Certificate certificate = keyStore.getCertificate(alias);
            if (certificate != null) {
                return certificate.getPublicKey();
            }
            return null;
        } catch (KeyStoreException e) {
            throw new CryptoException("Failed to extract public key", e);
        }
    }

    /**
     * <p>getCertificate.</p>
     *
     * @param alias a {@link java.lang.String} object.
     * @return a {@link java.security.cert.Certificate} object.
     */
    public java.security.cert.Certificate getCertificate(String alias) {
        this.initialize();
        try {
            return keyStore.getCertificate(alias);
        } catch (KeyStoreException e) {
            throw new CryptoException("Failed to extract certificate", e);
        }
    }

    /**
     * <p>getKeyPair.</p>
     *
     * @param alias    a {@link java.lang.String} object.
     * @param password an array of {@link char} objects.
     * @return a {@link java.security.KeyPair} object.
     */
    public KeyPair getKeyPair(String alias, char[] password) {
        this.initialize();
        try {
            Key key = keyStore.getKey(alias, password);
            if (key instanceof PrivateKey) {
                java.security.cert.Certificate certificate = keyStore.getCertificate(alias);
                if (certificate != null) {
                    return new KeyPair(certificate.getPublicKey(), (PrivateKey) key);
                }
            }
            throw new CryptoException("No key pair available for alias " + alias);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new CryptoException("Failed to extract private key", e);
        }
    }

    public static class CryptoKeyFactoryBuilder {
        private String type;
        private URL location;
        private String locationStr;
        private String password;
        private String providerName;
        private Provider provider;
        private String providerClassName;
        private KeyStore keyStore;

        CryptoKeyFactoryBuilder() {
        }

        public CryptoKeyFactory.CryptoKeyFactoryBuilder type(String type) {
            this.type = type;
            return this;
        }

        public CryptoKeyFactory.CryptoKeyFactoryBuilder location(URL location) {
            this.location = location;
            return this;
        }

        public CryptoKeyFactory.CryptoKeyFactoryBuilder locationStr(String locationStr) {
            this.locationStr = locationStr;
            return this;
        }

        public CryptoKeyFactory.CryptoKeyFactoryBuilder password(String password) {
            this.password = password;
            return this;
        }

        public CryptoKeyFactory.CryptoKeyFactoryBuilder providerName(String providerName) {
            this.providerName = providerName;
            return this;
        }

        public CryptoKeyFactory.CryptoKeyFactoryBuilder provider(Provider provider) {
            this.provider = provider;
            return this;
        }

        public CryptoKeyFactory.CryptoKeyFactoryBuilder providerClassName(String providerClassName) {
            this.providerClassName = providerClassName;
            return this;
        }

        public CryptoKeyFactory.CryptoKeyFactoryBuilder keyStore(KeyStore keyStore) {
            this.keyStore = keyStore;
            return this;
        }

        public CryptoKeyFactory build() {
            return new CryptoKeyFactory(type, location, locationStr, password, providerName, provider, providerClassName, keyStore);
        }

        public String toString() {
            return "CryptoKeyFactory.CryptoKeyFactoryBuilder(type=" + this.type + ", location=" + this.location + ", locationStr=" + this.locationStr + ", password=" + this.password + ", providerName=" + this.providerName + ", provider=" + this.provider + ", providerClassName=" + this.providerClassName + ", keyStore=" + this.keyStore + ")";
        }
    }
}
