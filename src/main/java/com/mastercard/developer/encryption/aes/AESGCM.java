package com.mastercard.developer.encryption.aes;

import com.mastercard.developer.encryption.jwe.JweObject;
import com.mastercard.developer.utils.ByteUtils;
import com.mastercard.developer.utils.EncodingUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;

public class AESGCM {

    private AESGCM() {
        // Nothing to do here
    }

    private static final String CYPHER = "AES/GCM/NoPadding";

    public static byte[] decrypt(Key cek, JweObject object) throws GeneralSecurityException {
        byte[] aad = object.getRawHeader().getBytes(StandardCharsets.US_ASCII);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, EncodingUtils.base64Decode(object.getIv()));
        byte[] bytes = ByteUtils.concat(EncodingUtils.base64Decode(object.getCipherText()), EncodingUtils.base64Decode(object.getAuthTag()));
        return cipher(cek, gcmSpec, bytes, aad, Cipher.DECRYPT_MODE);
    }

    public static byte[] cipher(Key key, GCMParameterSpec gcpSpec, byte[] bytes, byte[] aad, int mode) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CYPHER);
        cipher.init(mode, key, gcpSpec);
        cipher.updateAAD(aad);
        return cipher.doFinal(bytes);
    }
}
