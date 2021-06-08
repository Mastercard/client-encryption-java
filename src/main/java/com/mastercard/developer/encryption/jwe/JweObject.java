package com.mastercard.developer.encryption.jwe;

import com.mastercard.developer.encryption.EncryptionConfig;
import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;
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
import java.util.Base64;

public class JweObject {
    private final JweHeader header;
    private final String rawHeader;
    private final String encryptedKey;
    private final String iv;
    private final String cipherText;
    private final String authTag;

    private static final String A128CBC_HS256 = "A128CBC-HS256";
    private static final String A256GCM = "A256GCM";

    private JweObject(JweHeader header, String rawHeader, String encryptedKey, String iv, String cipherText, String authTag) {
        this.header = header;
        this.rawHeader = rawHeader;
        this.encryptedKey = encryptedKey;
        this.iv = iv;
        this.cipherText = cipherText;
        this.authTag = authTag;
    }

    public String decrypt(EncryptionConfig config) throws EncryptionException, GeneralSecurityException {
        Key cek = RSA.unwrapSecretKey(config.getDecryptionKey(), Base64.getUrlDecoder().decode(this.getEncryptedKey()), "SHA-256");
        String encryptionMethod = this.header.getEnc();

        byte[] plainText;

        if(encryptionMethod.equals(A256GCM)) {
            plainText = AESGCM.decrypt(cek, this);
        } else if(encryptionMethod.equals(A128CBC_HS256)) {
            plainText = AESCBC.decrypt(cek, this);
        } else {
            throw new EncryptionException(String.format("Encryption method %s not supported", encryptionMethod));
        }

        return new String(plainText);
    }

    public static String encrypt(EncryptionConfig config, String payload, JweHeader header) throws EncryptionException, GeneralSecurityException {
        SecretKeySpec cek = AESEncryption.generateCek(256);
        byte[] encryptedSecretKeyBytes = RSA.wrapSecretKey(config.getEncryptionCertificate().getPublicKey(), cek, "SHA-256");
        String encryptedKey = base64Encode(encryptedSecretKeyBytes);

        byte[] iv = AESEncryption.generateIv().getIV();
        byte[] payloadBytes = payload.getBytes();
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        String headerString = header.toJson();
        String encodedHeader = base64Encode(headerString.getBytes());

        byte[] aad = encodedHeader.getBytes(StandardCharsets.US_ASCII);

        SecretKeySpec aesKey = new SecretKeySpec(cek.getEncoded(), "AES");

        byte[] cipherOutput = AESGCM.cipher(aesKey, gcmSpec, payloadBytes, aad, Cipher.ENCRYPT_MODE);

        int tagPos = cipherOutput.length - ByteUtils.byteLength(128);
        byte[] cipherText = ByteUtils.subArray(cipherOutput, 0, tagPos);
        byte[] authTag = ByteUtils.subArray(cipherOutput, tagPos, ByteUtils.byteLength(128));

        return serialize(encodedHeader, encryptedKey, base64Encode(iv), base64Encode(cipherText), base64Encode(authTag));
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

    private static String base64Encode(byte[] bytes) {
        return EncodingUtils.encodeBytes(bytes, FieldLevelEncryptionConfig.FieldValueEncoding.BASE64);
    }

    public static JweObject parse(String encryptedPayload, JsonEngine jsonEngine) {
        String t = encryptedPayload.trim();
        int dot1 = t.indexOf('.');
        int dot2 = t.indexOf('.', dot1 + 1);
        int dot3 = t.indexOf('.', dot2 + 1);
        int dot4 = t.indexOf('.', dot3 + 1);
        JweHeader header = JweHeader.parseJweHeader(t.substring(0, dot1), jsonEngine);

        return new JweObject(header, t.substring(0, dot1), t.substring(dot1 + 1, dot2), t.substring(dot2 + 1, dot3), t.substring(dot3 + 1, dot4), t.substring(dot4 + 1));
    }

    public JweHeader getHeader() {
        return header;
    }

    public String getRawHeader() { return rawHeader; }

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
