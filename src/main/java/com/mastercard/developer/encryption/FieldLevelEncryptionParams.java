package com.mastercard.developer.encryption;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;
import java.security.Key;

import com.mastercard.developer.encryption.aes.AESEncryption;
import com.mastercard.developer.encryption.rsa.RSA;

import static com.mastercard.developer.utils.EncodingUtils.decodeValue;
import static com.mastercard.developer.utils.EncodingUtils.encodeBytes;

/**
 * Encryption parameters for computing field level encryption/decryption.
 */
public final class FieldLevelEncryptionParams {

    private static final Integer SYMMETRIC_KEY_SIZE = 128;
    static final String SYMMETRIC_KEY_TYPE = "AES";

    private final String ivValue;
    private final String encryptedKeyValue;
    private final String oaepPaddingDigestAlgorithmValue;
    private final FieldLevelEncryptionConfig config;
    private Key secretKey;
    private IvParameterSpec ivParameterSpec;

    public FieldLevelEncryptionParams(String ivValue, String encryptedKeyValue, String oaepPaddingDigestAlgorithmValue, FieldLevelEncryptionConfig config) {
        this.ivValue = ivValue;
        this.encryptedKeyValue = encryptedKeyValue;
        this.oaepPaddingDigestAlgorithmValue = oaepPaddingDigestAlgorithmValue;
        this.config = config;
    }

    /**
     * Generate encryption parameters.
     * @param config A {@link com.mastercard.developer.encryption.FieldLevelEncryptionConfig} instance
     * @return A {@link com.mastercard.developer.encryption.FieldLevelEncryptionParams} instance
     * @throws EncryptionException
     */
    public static FieldLevelEncryptionParams generate(FieldLevelEncryptionConfig config) throws EncryptionException {

        // Generate a random IV
        IvParameterSpec ivParameterSpec = AESEncryption.generateIv();
        String ivSpecValue = encodeBytes(ivParameterSpec.getIV(), config.fieldValueEncoding);

        // Generate an AES secret key
        SecretKey secretKey = generateSecretKey();

        // Encrypt the secret key
        byte[] encryptedSecretKeyBytes = RSA.wrapSecretKey(config.encryptionCertificate.getPublicKey(), secretKey, config.oaepPaddingDigestAlgorithm);
        String encryptedKeyValue = encodeBytes(encryptedSecretKeyBytes, config.fieldValueEncoding);

        // Compute the OAEP padding digest algorithm
        String oaepPaddingDigestAlgorithmValue = config.oaepPaddingDigestAlgorithm.replace("-", "");

        FieldLevelEncryptionParams params = new FieldLevelEncryptionParams(ivSpecValue, encryptedKeyValue,
                                                                           oaepPaddingDigestAlgorithmValue,
                                                                           config);
        params.secretKey = secretKey;
        params.ivParameterSpec = ivParameterSpec;
        return params;
    }

    public String getIvValue() {
        return ivValue;
    }

    public String getEncryptedKeyValue() {
        return encryptedKeyValue;
    }

    public String getOaepPaddingDigestAlgorithmValue() {
        return oaepPaddingDigestAlgorithmValue;
    }

    Key getSecretKey() throws EncryptionException {
        try {
            if (secretKey != null) {
                return secretKey;
            }
            // Decrypt the AES secret key
            byte[] encryptedSecretKeyBytes = decodeValue(encryptedKeyValue, config.fieldValueEncoding);
            secretKey = RSA.unwrapSecretKey(config.decryptionKey, encryptedSecretKeyBytes, oaepPaddingDigestAlgorithmValue);
            return secretKey;
        } catch (EncryptionException e) {
            throw e;
        } catch (Exception e) {
            throw new EncryptionException("Failed to decode and unwrap the provided secret key value!", e);
        }
    }

    @java.lang.SuppressWarnings("squid:S3329")
    IvParameterSpec getIvSpec() throws EncryptionException {
        try {
            if (ivParameterSpec != null) {
                return ivParameterSpec;
            }
            // Decode the IV
            byte[] ivByteArray = decodeValue(ivValue, config.fieldValueEncoding);
            ivParameterSpec = new IvParameterSpec(ivByteArray);
            return ivParameterSpec;
        } catch (Exception e) {
            throw new EncryptionException("Failed to decode the provided IV value!", e);
        }
    }

    private static SecretKey generateSecretKey() throws EncryptionException {
        try {
            KeyGenerator generator = KeyGenerator.getInstance(SYMMETRIC_KEY_TYPE);
            generator.init(SYMMETRIC_KEY_SIZE);
            return generator.generateKey();
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Failed to generate a secret key!", e);
        }
    }
}
