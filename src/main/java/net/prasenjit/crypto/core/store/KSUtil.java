package net.prasenjit.crypto.core.store;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * Created by prase on 09-06-2017.
 */
public class KSUtil {
    public static KeyStore load(String file, char[] password) {
        try (InputStream stream = new FileInputStream(file)) {
            KeyStore jceks = KeyStore.getInstance("JCEKS");
            jceks.load(stream, password);
            return jceks;
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
