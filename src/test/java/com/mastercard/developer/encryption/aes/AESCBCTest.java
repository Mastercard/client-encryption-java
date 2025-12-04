package com.mastercard.developer.encryption.aes;

import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.jwe.JweObject;
import com.mastercard.developer.json.JsonEngine;
import com.mastercard.developer.utils.EncodingUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class AESCBCTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testDecrypt_ShouldDecryptSuccessfully_WhenHmacVerificationIsEnabledAndTagIsValid() throws Exception {
        // Given: A properly constructed JWE with correct HMAC tag
        byte[] cekBytes = new byte[32]; // 256-bit key (128-bit HMAC key + 128-bit AES key)
        java.security.SecureRandom random = new java.security.SecureRandom();
        random.nextBytes(cekBytes);

        SecretKeySpec cek = new SecretKeySpec(cekBytes, "AES");
        SecretKeySpec hmacKey = new SecretKeySpec(cekBytes, 0, 16, "HmacSHA256");
        SecretKeySpec aesKey = new SecretKeySpec(cekBytes, 16, 16, "AES");

        // Encrypt data
        byte[] plainText = "Valid HMAC Test Data".getBytes(StandardCharsets.UTF_8);
        byte[] iv = new byte[16];
        random.nextBytes(iv);

        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, aesKey, new javax.crypto.spec.IvParameterSpec(iv));
        byte[] cipherText = cipher.doFinal(plainText);

        // Compute proper HMAC according to JWE spec
        String rawHeader = EncodingUtils.base64UrlEncode("{\"enc\":\"A128CBC-HS256\",\"alg\":\"RSA-OAEP-256\"}".getBytes());
        byte[] aad = rawHeader.getBytes(StandardCharsets.US_ASCII);

        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(hmacKey);
        mac.update(aad);
        mac.update(iv);
        mac.update(cipherText);

        // Add AL (AAD length in bits as 64-bit big-endian)
        long aadLengthBits = (long) aad.length * 8;
        java.nio.ByteBuffer alBuffer = java.nio.ByteBuffer.allocate(8);
        alBuffer.putLong(aadLengthBits);
        mac.update(alBuffer.array());

        byte[] hmacOutput = mac.doFinal();
        byte[] authTag = new byte[16]; // First 16 bytes (tag length = key length for A128CBC-HS256)
        System.arraycopy(hmacOutput, 0, authTag, 0, 16);

        // Construct JWE string
        String jweString = rawHeader + ".dummy." + EncodingUtils.base64UrlEncode(iv) + "." +
                          EncodingUtils.base64UrlEncode(cipherText) + "." + EncodingUtils.base64UrlEncode(authTag);
        JweObject jweObject = JweObject.parse(jweString, JsonEngine.getDefault());

        // When: Decrypt with HMAC verification enabled
        byte[] result = AESCBC.decrypt(cek, jweObject, true);

        // Then: Should succeed and return correct plaintext
        assertNotNull(result);
        assertEquals("Valid HMAC Test Data", new String(result, StandardCharsets.UTF_8));
    }

    @Test
    public void testDecrypt_ShouldThrowException_WhenHmacVerificationIsEnabledAndTagIsInvalid() throws Exception {
        // Given: A JWE object with an invalid HMAC tag
        String rawHeader = EncodingUtils.base64UrlEncode("{\"enc\":\"A128CBC-HS256\",\"alg\":\"RSA-OAEP-256\"}".getBytes());

        // Create a JWE string with intentionally wrong auth tag
        String encryptedKey = "dummy_encrypted_key_base64url";
        String iv = EncodingUtils.base64UrlEncode(new byte[16]); // 16-byte IV
        String cipherText = EncodingUtils.base64UrlEncode("encrypted_data".getBytes());
        String invalidAuthTag = EncodingUtils.base64UrlEncode(new byte[16]); // Wrong tag

        String jweString = rawHeader + "." + encryptedKey + "." + iv + "." + cipherText + "." + invalidAuthTag;
        JweObject jweObject = JweObject.parse(jweString, JsonEngine.getDefault());

        // When/Then: Decryption should fail with authentication tag verification error
        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage("Authentication tag verification failed");

        // Create a dummy CEK
        byte[] cekBytes = new byte[32]; // 256-bit key
        SecretKeySpec cek = new SecretKeySpec(cekBytes, "AES");

        AESCBC.decrypt(cek, jweObject, true);
    }

    @Test
    public void testDecrypt_ShouldDecryptWithoutVerification_WhenHmacVerificationIsDisabled() throws Exception {
        // Given: A JWE object (even with wrong HMAC tag)
        String rawHeader = EncodingUtils.base64UrlEncode("{\"enc\":\"A128CBC-HS256\",\"alg\":\"RSA-OAEP-256\"}".getBytes());

        // Create a simple encrypted payload using AES-CBC
        byte[] cekBytes = new byte[32]; // 256-bit key
        SecretKeySpec cek = new SecretKeySpec(cekBytes, "AES");

        // Encrypt some data first
        byte[] plainText = "test".getBytes(StandardCharsets.UTF_8);
        byte[] iv = new byte[16]; // Zero IV for testing

        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
        javax.crypto.spec.SecretKeySpec aesKey = new javax.crypto.spec.SecretKeySpec(cekBytes, 16, 16, "AES");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, aesKey, new javax.crypto.spec.IvParameterSpec(iv));
        byte[] encrypted = cipher.doFinal(plainText);

        String encryptedKey = "dummy_encrypted_key_base64url";
        String ivB64 = EncodingUtils.base64UrlEncode(iv);
        String cipherTextB64 = EncodingUtils.base64UrlEncode(encrypted);
        String authTag = EncodingUtils.base64UrlEncode(new byte[16]); // Wrong tag, but should be ignored

        String jweString = rawHeader + "." + encryptedKey + "." + ivB64 + "." + cipherTextB64 + "." + authTag;
        JweObject jweObject = JweObject.parse(jweString, JsonEngine.getDefault());

        // When: Decrypt with HMAC verification disabled
        byte[] result = AESCBC.decrypt(cek, jweObject, false);

        // Then: Should succeed and return decrypted data
        assertNotNull(result);
        assertEquals("test", new String(result, StandardCharsets.UTF_8));
    }

    @Test
    public void testDecrypt_ShouldUseCorrectKeySplit_WhenDecrypting() throws Exception {
        // Given: A 256-bit CEK that should be split into HMAC key (first 128 bits) and AES key (second 128 bits)
        byte[] cekBytes = new byte[32];
        // Fill with a pattern to verify correct split
        for (int i = 0; i < 16; i++) {
            cekBytes[i] = (byte) 0xAA; // HMAC key part
            cekBytes[i + 16] = (byte) 0xBB; // AES key part
        }
        SecretKeySpec cek = new SecretKeySpec(cekBytes, "AES");

        // Create encrypted data using only the second half (AES key)
        byte[] plainText = "testdata".getBytes(StandardCharsets.UTF_8);
        byte[] iv = new byte[16];

        javax.crypto.spec.SecretKeySpec aesKey = new javax.crypto.spec.SecretKeySpec(cekBytes, 16, 16, "AES");
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, aesKey, new javax.crypto.spec.IvParameterSpec(iv));
        byte[] encrypted = cipher.doFinal(plainText);

        String rawHeader = EncodingUtils.base64UrlEncode("{\"enc\":\"A128CBC-HS256\",\"alg\":\"RSA-OAEP-256\"}".getBytes());
        String jweString = rawHeader + ".dummy." + EncodingUtils.base64UrlEncode(iv) + "." +
                          EncodingUtils.base64UrlEncode(encrypted) + "." + EncodingUtils.base64UrlEncode(new byte[16]);
        JweObject jweObject = JweObject.parse(jweString, JsonEngine.getDefault());

        // When: Decrypt without HMAC verification (to avoid tag mismatch)
        byte[] result = AESCBC.decrypt(cek, jweObject, false);

        // Then: Should correctly use the second half of CEK for decryption
        assertEquals("testdata", new String(result, StandardCharsets.UTF_8));
    }

    @Test
    public void testDecrypt_ShouldComputeCorrectHmac_WhenVerificationIsEnabled() throws Exception {
        // Given: A properly constructed JWE with correct HMAC
        byte[] cekBytes = new byte[32];
        java.security.SecureRandom random = new java.security.SecureRandom();
        random.nextBytes(cekBytes);

        SecretKeySpec cek = new SecretKeySpec(cekBytes, "AES");
        SecretKeySpec hmacKey = new SecretKeySpec(cekBytes, 0, 16, "HmacSHA256");
        SecretKeySpec aesKey = new SecretKeySpec(cekBytes, 16, 16, "AES");

        // Encrypt data
        byte[] plainText = "Hello, World!".getBytes(StandardCharsets.UTF_8);
        byte[] iv = new byte[16];
        random.nextBytes(iv);

        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, aesKey, new javax.crypto.spec.IvParameterSpec(iv));
        byte[] cipherText = cipher.doFinal(plainText);

        // Compute proper HMAC
        String rawHeader = EncodingUtils.base64UrlEncode("{\"enc\":\"A128CBC-HS256\",\"alg\":\"RSA-OAEP-256\"}".getBytes());
        byte[] aad = rawHeader.getBytes(StandardCharsets.US_ASCII);

        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(hmacKey);
        mac.update(aad);
        mac.update(iv);
        mac.update(cipherText);

        // Add AL (AAD length in bits as 64-bit big-endian)
        long aadLengthBits = (long) aad.length * 8;
        java.nio.ByteBuffer alBuffer = java.nio.ByteBuffer.allocate(8);
        alBuffer.putLong(aadLengthBits);
        mac.update(alBuffer.array());

        byte[] hmacOutput = mac.doFinal();
        byte[] authTag = new byte[16]; // First 16 bytes
        System.arraycopy(hmacOutput, 0, authTag, 0, 16);

        // Construct JWE
        String jweString = rawHeader + ".dummy." + EncodingUtils.base64UrlEncode(iv) + "." +
                          EncodingUtils.base64UrlEncode(cipherText) + "." + EncodingUtils.base64UrlEncode(authTag);
        JweObject jweObject = JweObject.parse(jweString, JsonEngine.getDefault());

        // When: Decrypt with HMAC verification enabled
        byte[] result = AESCBC.decrypt(cek, jweObject, true);

        // Then: Should succeed and return correct plaintext
        assertEquals("Hello, World!", new String(result, StandardCharsets.UTF_8));
    }
}

