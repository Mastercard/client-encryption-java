package com.mastercard.developer.encryption.aes;

import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.utils.ByteUtils;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public class AESEncryption {

    private AESEncryption() {
        // Nothing to do here
    }

    public static IvParameterSpec generateIv() throws EncryptionException {
        try {
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            byte[] ivBytes = new byte[16];
            secureRandom.nextBytes(ivBytes);
            return new IvParameterSpec(ivBytes);
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Failed to generate an IV value!", e);
        }
    }

    public static SecretKeySpec generateCek(int bitLength) {
        SecureRandom random = new SecureRandom();
        byte[] cekMaterial = new byte[ByteUtils.byteLength(bitLength)];
        random.nextBytes(cekMaterial);
        return new SecretKeySpec(cekMaterial, "AES");
    }
}
