package com.mastercard.developer.encryption.jwe;

import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.JweConfig;
import com.mastercard.developer.json.JsonEngine;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;

import static com.mastercard.developer.utils.EncryptionUtils.generateIv;

public class JWEObject {
    private JWEHeader header;
    private String rawHeader;
    private String encryptedKey;
    private String iv;
    private String cipherText;
    private String authTag;

    private static final String ASYMMETRIC_CYPHER = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private JWEObject(JWEHeader header, String rawHeader, String encryptedKey, String iv, String cipherText, String authTag) {
        this.header = header;
        this.rawHeader = rawHeader;
        this.encryptedKey = encryptedKey;
        this.iv = iv;
        this.cipherText = cipherText;
        this.authTag = authTag;
    }

    public String decrypt(JweConfig config, String cypher) throws EncryptionException {
        SecretKey cek = decryptKey(config, Base64Codec.decode(this.getEncryptedKey()));
        String encodedHeader = this.getRawHeader();

        byte[] aad = encodedHeader.getBytes(StandardCharsets.US_ASCII);
        byte[] plainText;

        SecretKey aesKey = new SecretKeySpec(cek.getEncoded(), "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, Base64Codec.decode(this.getIv()));

        try {
            Cipher cipher = Cipher.getInstance(cypher);
            cipher.init(2, aesKey, gcmSpec);
            cipher.updateAAD(aad);
            plainText = cipher.doFinal(ByteUtils.concat(Base64Codec.decode(this.getCipherText()), Base64Codec.decode(this.getAuthTag())));
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Payload decryption failed!", e);
        }

        return new String(plainText);
    }

    public static String encrypt(JweConfig config, String payload, JWEHeader header) throws EncryptionException {
        SecretKeySpec cek = generateCek();
        byte[] encryptedSecretKeyBytes = encryptKey(config, cek);
        String encryptedKey = base64Encode(encryptedSecretKeyBytes);

        byte[] iv = generateIv().getIV();
        byte[] payloadBytes = payload.getBytes();
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        String headerString = header.toJSONObject().toString();
        String encodedHeader = base64Encode(headerString);

        byte[] aad = encodedHeader.getBytes(StandardCharsets.US_ASCII);

        SecretKeySpec aesKey = new SecretKeySpec(cek.getEncoded(), "AES");

        byte[] cipherOutput;

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(1, aesKey, gcmSpec);
            cipher.updateAAD(aad);
            cipherOutput = cipher.doFinal(payloadBytes);
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Payload encryption failed!", e);
        }

        int tagPos = cipherOutput.length - ByteUtils.byteLength(128);
        byte[] cipherText = ByteUtils.subArray(cipherOutput, 0, tagPos);
        byte[] authTag = ByteUtils.subArray(cipherOutput, tagPos, ByteUtils.byteLength(128));

        return serialize(encodedHeader, encryptedKey, base64Encode(iv), base64Encode(cipherText), base64Encode(authTag));
    }

    private static String serialize(String header, String encryptedKey, String iv, String cipherText, String authTag) {
        StringBuilder sb = new StringBuilder(header);
        sb.append('.');
        sb.append(encryptedKey);
        sb.append('.');
        sb.append(iv);
        sb.append('.');
        sb.append(cipherText);
        sb.append('.');
        sb.append(authTag);
        return sb.toString();
    }

    private static String base64Encode(String text) {
        byte[] bytes = text.getBytes();
        return Base64Codec.encodeToString(bytes);
    }

    private static String base64Encode(byte[] bytes) {
        return Base64Codec.encodeToString(bytes);
    }

    private static byte[] encryptKey(JweConfig config, Key key) throws EncryptionException {
        try {
            AlgorithmParameters algp = AlgorithmParameters.getInstance("OAEP");
            Key publicEncryptionKey = config.getEncryptionCertificate().getPublicKey();
            AlgorithmParameterSpec paramSpec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
            algp.init(paramSpec);
            Cipher cipher = Cipher.getInstance(ASYMMETRIC_CYPHER);
            cipher.init(Cipher.ENCRYPT_MODE, publicEncryptionKey, algp);
            return cipher.doFinal(key.getEncoded());
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Failed to wrap secret key!", e);
        }
    }

    private static SecretKeySpec decryptKey(JweConfig config, byte[] encryptedCEK) throws EncryptionException {
        try {
            AlgorithmParameters algp = AlgorithmParameters.getInstance("OAEP");
            AlgorithmParameterSpec paramSpec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
            algp.init(paramSpec);
            Cipher cipher = Cipher.getInstance(ASYMMETRIC_CYPHER);
            cipher.init(Cipher.DECRYPT_MODE, config.getDecryptionKey(), algp);
            return new SecretKeySpec(cipher.doFinal(encryptedCEK), "AES");
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Failed to wrap secret key!", e);
        }
    }

    private static SecretKeySpec generateCek() {
        SecureRandom random = new SecureRandom();
        byte[] cekMaterial = new byte[ByteUtils.byteLength(256)];
        random.nextBytes(cekMaterial);
        return new SecretKeySpec(cekMaterial, "AES");
    }

    public static JWEObject parse(String encryptedPayload, JsonEngine jsonEngine) {
        String t = encryptedPayload.trim();
        int dot1 = t.indexOf('.');
        int dot2 = t.indexOf('.', dot1 + 1);
        int dot3 = t.indexOf('.', dot2 + 1);
        int dot4 = t.indexOf('.', dot3 + 1);
        JWEHeader header = JWEHeader.parseJweHeader(t.substring(0, dot1), jsonEngine);

        return new JWEObject(header, t.substring(0, dot1), t.substring(dot1 + 1, dot2), t.substring(dot2 + 1, dot3), t.substring(dot3 + 1, dot4), t.substring(dot4 + 1));
    }

    public JWEHeader getHeader() {
        return header;
    }

    private String getRawHeader() { return rawHeader; }

    private String getEncryptedKey() {
        return encryptedKey;
    }

    private String getIv() {
        return iv;
    }

    private String getCipherText() {
        return cipherText;
    }

    private String getAuthTag() {
        return authTag;
    }
}
