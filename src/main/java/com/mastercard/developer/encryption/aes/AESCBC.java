package com.mastercard.developer.encryption.aes;

import com.mastercard.developer.encryption.jwe.JweObject;
import com.mastercard.developer.utils.EncodingUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

public class AESCBC {

    private AESCBC() {
    }

    private static final String CYPHER = "AES/GCM/NoPadding";

    @java.lang.SuppressWarnings("squid:S3329")
    public static byte[] decrypt(Key secretKey, JweObject object) throws GeneralSecurityException {
        // First 16 bytes are the MAC key, so we only use the second 16 bytes
        SecretKeySpec aesKey = new SecretKeySpec(secretKey.getEncoded(), 16, 16, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, EncodingUtils.base64Decode(object.getIv()));
        byte[] cipherText = EncodingUtils.base64Decode(object.getCipherText());
        byte[] iv = EncodingUtils.base64Decode(object.getIv());

        return cipher(aesKey, gcmSpec, new IvParameterSpec(iv), cipherText, Cipher.DECRYPT_MODE);
    }

    public static byte[] cipher(Key key,GCMParameterSpec gcpSpec, AlgorithmParameterSpec iv, byte[] bytes, int mode) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CYPHER);
        cipher.init(mode, key, gcpSpec, iv);
        return cipher.doFinal(bytes);
    }
}
