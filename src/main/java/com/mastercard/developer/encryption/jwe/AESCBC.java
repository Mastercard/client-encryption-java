package com.mastercard.developer.encryption.jwe;

import com.mastercard.developer.encryption.EncryptionException;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

public class AESCBC {
    private static final String CYPHER = "AES/CBC/PKCS5Padding";

    public static byte[] decrypt(SecretKey secretKey, JWEObject object) throws EncryptionException {
        SecretKeySpec aesKey = new SecretKeySpec(secretKey.getEncoded(), 16, 16, "AES");

        byte[] cipherText = Base64Codec.decode(object.getCipherText());
        byte[] iv = Base64Codec.decode(object.getIv());

        try {
            Cipher cipher = Cipher.getInstance(CYPHER);
            SecretKeySpec keyspec = new SecretKeySpec(aesKey.getEncoded(), "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(2, keyspec, ivSpec);

            return cipher.doFinal(cipherText);
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Payload decryption failed!", e);
        }
    }
}
