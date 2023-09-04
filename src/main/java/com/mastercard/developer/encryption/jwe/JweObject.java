package com.mastercard.developer.encryption.jwe;

import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.JweConfig;
import com.mastercard.developer.encryption.aes.AESCBC;
import com.mastercard.developer.encryption.aes.AESEncryption;
import com.mastercard.developer.encryption.aes.AESGCM;
import com.mastercard.developer.encryption.rsa.RSA;
import com.mastercard.developer.json.JsonEngine;
import com.mastercard.developer.utils.ByteUtils;
import com.mastercard.developer.utils.EncodingUtils;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class JweObject {
    private final JweHeader header;
    private final String rawHeader;
    private final String encryptedKey;
    private final String iv;
    private final String cipherText;
    private final String authTag;

    private static final String A128CBC_HS256 = "A128CBC-HS256";
    private static final List<String> AES_GCM_ENCRYPTION_METHODS = Arrays.asList("A128GCM", "A192GCM", "A256GCM");

    private JweObject(JweHeader header, String rawHeader, String encryptedKey, String iv, String cipherText, String authTag) {
        this.header = header;
        this.rawHeader = rawHeader;
        this.encryptedKey = encryptedKey;
        this.iv = iv;
        this.cipherText = cipherText;
        this.authTag = authTag;
    }

    public String decrypt(JweConfig config) throws EncryptionException, GeneralSecurityException {
        Key cek = RSA.unwrapSecretKey(config.getDecryptionKey(), Base64.getUrlDecoder().decode(this.getEncryptedKey()), "SHA-256");
        String encryptionMethod = this.header.getEnc();

        byte[] plainText;

        if (AES_GCM_ENCRYPTION_METHODS.contains(encryptionMethod)) {
            plainText = AESGCM.decrypt(cek, this);
        } else if (encryptionMethod.equals(A128CBC_HS256)) {
            plainText = AESCBC.decrypt(cek, this);
        } else {
            throw new EncryptionException(String.format("Encryption method %s not supported", encryptionMethod));
        }

        return new String(plainText);
    }

    public static String encrypt(JweConfig config, String payload, JweHeader header) throws EncryptionException, GeneralSecurityException {
        SecretKeySpec cek = AESEncryption.generateCek(256);
        byte[] encryptedSecretKeyBytes = RSA.wrapSecretKey(config.getEncryptionKey(), cek, "SHA-256");
        String encryptedKey = EncodingUtils.base64UrlEncode(encryptedSecretKeyBytes);

        byte[] iv = AESEncryption.generateIv().getIV();
        byte[] payloadBytes = payload.getBytes();
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        String headerString = header.toJson();
        String encodedHeader = EncodingUtils.base64UrlEncode(headerString.getBytes());

        byte[] aad = encodedHeader.getBytes(StandardCharsets.US_ASCII);

        SecretKeySpec aesKey = new SecretKeySpec(cek.getEncoded(), "AES");

        byte[] cipherOutput = AESGCM.cipher(aesKey, gcmSpec, payloadBytes, aad, Cipher.ENCRYPT_MODE);

        int tagPos = cipherOutput.length - ByteUtils.byteLength(128);
        byte[] cipherText = ByteUtils.subArray(cipherOutput, 0, tagPos);
        byte[] authTag = ByteUtils.subArray(cipherOutput, tagPos, ByteUtils.byteLength(128));

        return serialize(encodedHeader, encryptedKey, EncodingUtils.base64UrlEncode(iv), EncodingUtils.base64UrlEncode(cipherText), EncodingUtils.base64UrlEncode(authTag));
    }

    private static String serialize(String header, String encryptedKey, String iv, String cipherText, String authTag) {
        return header + '.' +
                encryptedKey +
                '.' +
                iv +
                '.' +
                cipherText +
                '.' +
                authTag;
    }

    public static JweObject parse(String encryptedPayload, JsonEngine jsonEngine) {
        String[] payloadParts = encryptedPayload.trim()
                .split("\\.");

        String rawHeader = payloadParts[0];
        String encryptedKey = payloadParts[1];
        String iv = payloadParts[2];
        String cipherText = payloadParts[3];
        String authTag = payloadParts[4];
        JweHeader header = JweHeader.parseJweHeader(rawHeader, jsonEngine);

        return new JweObject(header, rawHeader, encryptedKey, iv, cipherText, authTag);
    }

    public JweHeader getHeader() {
        return header;
    }

    public String getRawHeader() {
        return rawHeader;
    }

    private String getEncryptedKey() {
        return encryptedKey;
    }

    public String getIv() {
        return iv;
    }

    public String getCipherText() {
        return cipherText;
    }

    public String getAuthTag() {
        return authTag;
    }
}
