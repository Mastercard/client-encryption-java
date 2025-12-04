package com.mastercard.developer.encryption.aes;

import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.jwe.JweObject;
import com.mastercard.developer.utils.ByteUtils;
import com.mastercard.developer.utils.EncodingUtils;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.spec.AlgorithmParameterSpec;

public class AESCBC {

    private AESCBC() {
    }

    @java.lang.SuppressWarnings("java:S5542")
    private static final String CIPHER = "AES/CBC/PKCS5Padding";
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    @java.lang.SuppressWarnings("squid:S3329")
    public static byte[] decrypt(Key secretKey, JweObject object, boolean enableHmacVerification) throws GeneralSecurityException, EncryptionException {
        byte[] cek = secretKey.getEncoded();

       if(cek.length != 32) {
          throw new IllegalArgumentException("CEK should be of length 32");
       }
        // For A128CBC-HS256: First 16 bytes are HMAC key, second 16 bytes are AES key
        int keyLength = cek.length / 2;
        SecretKeySpec aesKey = new SecretKeySpec(cek, keyLength, keyLength, "AES");

        byte[] cipherText = EncodingUtils.base64Decode(object.getCipherText());
        byte[] iv = EncodingUtils.base64Decode(object.getIv());

        // Only verify authentication tag if enabled
        if (enableHmacVerification) {
            SecretKeySpec hmacKey = new SecretKeySpec(cek, 0, keyLength, HMAC_ALGORITHM);
            byte[] authTag = EncodingUtils.base64Decode(object.getAuthTag());
            byte[] aad = object.getRawHeader().getBytes(StandardCharsets.US_ASCII);

            byte[] expectedTag = computeAuthTag(hmacKey, aad, iv, cipherText, keyLength);
            if (!MessageDigest.isEqual(authTag, expectedTag)) {
                throw new EncryptionException("Authentication tag verification failed");
            }
        }

        return cipher(aesKey, new IvParameterSpec(iv), cipherText, Cipher.DECRYPT_MODE);
    }

    public static byte[] cipher(Key key, AlgorithmParameterSpec iv, byte[] bytes, int mode) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(mode, key, iv);
        return cipher.doFinal(bytes);
    }

    /**
     * Computes the authentication tag for AES-CBC-HMAC-SHA2
     * HMAC is computed over: AAD || IV || Ciphertext || AL
     * where AL is the length of AAD in bits expressed as a 64-bit big-endian integer
     */
    private static byte[] computeAuthTag(SecretKeySpec hmacKey, byte[] aad, byte[] iv, byte[] cipherText, int tagLength)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(hmacKey);

        // Compute AL (AAD Length in bits as 64-bit big-endian)
        long aadLengthBits = (long) aad.length * 8;
        byte[] al = ByteBuffer.allocate(8).putLong(aadLengthBits).array();

        // HMAC input: AAD || IV || Ciphertext || AL
        mac.update(aad);
        mac.update(iv);
        mac.update(cipherText);
        mac.update(al);

        byte[] hmacOutput = mac.doFinal();

        // Return first half (tagLength bytes) as the authentication tag
        return ByteUtils.subArray(hmacOutput, 0, tagLength);
    }
}
