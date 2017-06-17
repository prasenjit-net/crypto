package net.prasenjit.crypto.core;

import org.apache.commons.codec.binary.Base64;

/**
 * Created by prase on 06-06-2017.
 */
public interface TextEncryptor extends Encryptor {
    default String encrypt(String data) {
        byte[] encryptedData = encrypt(data.getBytes());
        return Base64.encodeBase64String(encryptedData);
    }

    default String decrypt(String data) {
        byte[] encryptedData = Base64.decodeBase64(data);
        byte[] decryptedData = decrypt(encryptedData);
        return new String(decryptedData);
    }
}
