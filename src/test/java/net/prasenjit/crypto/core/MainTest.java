package net.prasenjit.crypto.core;

import net.prasenjit.crypto.core.store.CryptoKeyFactory;
import net.prasenjit.crypto.core.store.KSUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.cert.*;

/**
 * Created by prase on 09-06-2017.
 */
public class MainTest {

    @Test
    public void testDSA() {
        final String testData = "Hello World!";
        KeyStore store = KSUtil.load("crypto.jks", "crypto".toCharArray());
        try {
            Key key = store.getKey("3des1", "3des1".toCharArray());
            System.out.println(key);
            System.out.println(key.getAlgorithm());
            System.out.println(key.getFormat());

            SecureRandom secureRandom = new SecureRandom();
            byte[] ivBytes = new byte[8];
            secureRandom.nextBytes(ivBytes);
            final IvParameterSpec iv = new IvParameterSpec(ivBytes);
            final Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            byte[] encrypted = cipher.doFinal(testData.getBytes());
            byte[] dataTobeSent = ArrayUtils.addAll(encrypted, ivBytes);

            String encString = Base64.encodeBase64String(dataTobeSent);
            System.out.println(encString);

            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            byte[] bytes = cipher.doFinal(dataTobeSent, 0, dataTobeSent.length - 8);
            String original = new String(bytes);

            System.out.println(original);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testRSA() throws Exception {
        final String testData = "Hello Encrypted World!";
        KeyStore store = KSUtil.load("crypto.jks", "crypto".toCharArray());

        String alias = "rsa1";
        Key key = store.getKey(alias, alias.toCharArray());
        if (key instanceof PrivateKey) {
            // Get certificate of public key
            java.security.cert.Certificate cert = store.getCertificate(alias);

            // Get public key
            PublicKey publicKey = cert.getPublicKey();

            // Return a key pair
            KeyPair keyPair = new KeyPair(publicKey, (PrivateKey) key);
//            System.out.println(keyPair);

            Cipher encryptor = Cipher.getInstance("RSA");
            encryptor.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());

            Cipher decryptor = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            decryptor.init(Cipher.DECRYPT_MODE, keyPair.getPublic());

            byte[] encryptedBytes = encryptor.doFinal(testData.getBytes());
            System.out.println(Base64.encodeBase64String(encryptedBytes));

            byte[] bytes = decryptor.doFinal(encryptedBytes);
            System.out.println(new String(bytes));
        }
    }

    @Test
    public void testFactory() {
        CryptoKeyFactory factory = CryptoKeyFactory.builder()
                .locationStr("file:crypto.jks").type("JCEKS")
                .password("crypto").build();
        KeyPair keyPair = factory.getKeyPair("rsa1", "rsa1".toCharArray());
        Assert.assertNotNull(keyPair);
    }
}