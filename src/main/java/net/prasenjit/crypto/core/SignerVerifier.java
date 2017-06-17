package net.prasenjit.crypto.core;

import org.apache.commons.codec.binary.Base64;

/**
 * Created by prase on 17-06-2017.
 */
public interface SignerVerifier {
    byte[] sign(byte[] data);

    default String sign(String data) {
        byte[] encryptedData = sign(data.getBytes());
        return Base64.encodeBase64String(encryptedData);
    }

    boolean verify(byte[] data, byte[] signature);

    default boolean verify(String data, String signature) {
        byte[] sign = Base64.decodeBase64(signature);
        return verify(data.getBytes(), sign);
    }
}
