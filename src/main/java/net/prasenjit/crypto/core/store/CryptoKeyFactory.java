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

package net.prasenjit.crypto.core.store;

import lombok.Builder;
import lombok.extern.java.Log;
import net.prasenjit.crypto.core.exception.CryptoException;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.logging.Level;

/**
 * Created by prase on 09-06-2017.
 */
@Log
@Builder
public class CryptoKeyFactory {
    private String type = "JKS";
    private URL location;
    private String locationStr;
    private String password = "changeit";
    private String providerName;
    private Provider provider;
    private String providerClassName;

    private transient KeyStore keyStore;

    private synchronized void initilize() {
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
            throw new CryptoException("Failed to instanciate key store", e);
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

    public SecretKey getSecretKey(String alias, char[] password) {
        this.initilize();
        try {
            Key key = keyStore.getKey(alias, password);
            if (key != null && key instanceof SecretKey) {
                return (SecretKey) key;
            }
            return null;
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new CryptoException("Failed to extract secret key", e);
        }
    }

    public PrivateKey getPrivateKey(String alias, char[] password) {
        this.initilize();
        try {
            Key key = keyStore.getKey(alias, password);
            if (key != null && key instanceof PrivateKey) {
                return (PrivateKey) key;
            }
            return null;
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new CryptoException("Failed to extract private key", e);
        }
    }

    public PublicKey getPublicKey(String alias) {
        this.initilize();
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

    public java.security.cert.Certificate getCertificate(String alias) {
        this.initilize();
        try {
            return keyStore.getCertificate(alias);
        } catch (KeyStoreException e) {
            throw new CryptoException("Failed to extract certificate", e);
        }
    }

    public KeyPair getKeyPair(String alias, char[] password) {
        this.initilize();
        try {
            Key key = keyStore.getKey(alias, password);
            if (key != null && key instanceof PrivateKey) {
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
}
