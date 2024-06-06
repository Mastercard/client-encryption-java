package com.mastercard.developer.encryption.aes;

import com.mastercard.developer.encryption.jwe.JweObject;
import com.mastercard.developer.utils.ByteUtils;
import com.mastercard.developer.utils.EncodingUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;

public class AESCBC {

    private AESCBC() {
    }

    private static final String CYPHER = "AES/GCM/NoPadding";

    @java.lang.SuppressWarnings("squid:S3329")
    public static byte[] decrypt(Key secretKey, JweObject object) throws GeneralSecurityException {
        byte[] aad = object.getRawHeader().getBytes(StandardCharsets.US_ASCII);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, EncodingUtils.base64Decode(object.getIv()));
        byte[] bytes = ByteUtils.concat(EncodingUtils.base64Decode(object.getCipherText()), EncodingUtils.base64Decode(object.getAuthTag()));

        return cipher(secretKey, gcmSpec, bytes, aad, Cipher.DECRYPT_MODE);
    }

    public static byte[] cipher(Key key, GCMParameterSpec gcmSpec, byte[] bytes, aad, int mode) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CYPHER);
        cipher.init(mode, key, gcpSpec);
        cipher.updateAAD(aad);
        return cipher.doFinal(bytes);
    }
}
