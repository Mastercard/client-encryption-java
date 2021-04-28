package com.mastercard.developer.encryption.jwe;

import com.mastercard.developer.encryption.EncryptionException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

public class AESGCM {
    private static final String CIPHER = "AES/GCM/NoPadding";

    public static byte[] decrypt(SecretKey cek, JWEObject obj) throws EncryptionException {
        byte[] aad = obj.getRawHeader().getBytes(StandardCharsets.US_ASCII);
        SecretKey aesKey = new SecretKeySpec(cek.getEncoded(), "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, Base64Codec.decode(obj.getIv()));

        try {
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(2, aesKey, gcmSpec);
            cipher.updateAAD(aad);
            return cipher.doFinal(ByteUtils.concat(Base64Codec.decode(obj.getCipherText()), Base64Codec.decode(obj.getAuthTag())));
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Payload decryption failed!", e);
        }
    }
}
