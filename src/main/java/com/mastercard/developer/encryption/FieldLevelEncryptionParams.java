package com.mastercard.developer.encryption;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;

import static com.mastercard.developer.encryption.FieldLevelEncryptionConfig.FieldValueEncoding;
import static com.mastercard.developer.utils.EncodingUtils.decodeValue;
import static com.mastercard.developer.utils.EncodingUtils.encodeBytes;
import static com.mastercard.developer.utils.StringUtils.isNullOrEmpty;

/**
 * Encryption parameters for computing field level encryption/decryption.
 */
public final class FieldLevelEncryptionParams {

    private static final Integer SYMMETRIC_KEY_SIZE = 128;
    protected static final String SYMMETRIC_KEY_TYPE = "AES";
    private static final String ASYMMETRIC_CYPHER = "RSA/ECB/OAEPWith{ALG}AndMGF1Padding";
    private static final String SUN_JCE = "SunJCE";

    private final String ivValue;
    private final String encryptedKeyValue;
    private final String oaepPaddingDigestAlgorithmValue;
    private final String encryptionCertificateFingerprintValue;
    private final String encryptionKeyFingerprintValue;
    private final FieldLevelEncryptionConfig config;
    private Key secretKey;
    private IvParameterSpec ivParameterSpec;

    public FieldLevelEncryptionParams(String ivValue, String encryptedKeyValue,
                                      String oaepPaddingDigestAlgorithmValue, String encryptionCertificateFingerprintValue,
                                      String encryptionKeyFingerprintValue, FieldLevelEncryptionConfig config) {
        this.ivValue = ivValue;
        this.encryptedKeyValue = encryptedKeyValue;
        this.oaepPaddingDigestAlgorithmValue = oaepPaddingDigestAlgorithmValue;
        this.encryptionCertificateFingerprintValue = encryptionCertificateFingerprintValue;
        this.encryptionKeyFingerprintValue = encryptionKeyFingerprintValue;
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
        IvParameterSpec ivParameterSpec = generateIv();
        String ivSpecValue = encodeBytes(ivParameterSpec.getIV(), config.fieldValueEncoding);

        // Generate an AES secret key
        SecretKey secretKey = generateSecretKey();

        // Encrypt the secret key
        byte[] encryptedSecretKeyBytes = wrapSecretKey(config, secretKey);
        String encryptedKeyValue = encodeBytes(encryptedSecretKeyBytes, config.fieldValueEncoding);

        // Compute fingerprints and OAEP padding digest algorithm
        String encryptionCertificateFingerprint = getOrComputeEncryptionCertificateFingerprint(config);
        String encryptionKeyFingerprint = getOrComputeEncryptionKeyFingerprint(config);
        String oaepPaddingDigestAlgorithmValue = config.oaepPaddingDigestAlgorithm.replace("-", "");

        FieldLevelEncryptionParams params = new FieldLevelEncryptionParams(ivSpecValue, encryptedKeyValue,
                                                                           oaepPaddingDigestAlgorithmValue, encryptionCertificateFingerprint,
                                                                           encryptionKeyFingerprint, config);
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

    public String getEncryptionCertificateFingerprintValue() {
        return encryptionCertificateFingerprintValue;
    }

    public String getEncryptionKeyFingerprintValue() {
        return encryptionKeyFingerprintValue;
    }

    public String getOaepPaddingDigestAlgorithmValue() {
        return oaepPaddingDigestAlgorithmValue;
    }

    public Key getSecretKey() throws EncryptionException {
        try {
            if (secretKey != null) {
                return secretKey;
            }
            // Decrypt the AES secret key
            byte[] encryptedSecretKeyBytes = decodeValue(encryptedKeyValue, config.fieldValueEncoding);
            secretKey = FieldLevelEncryptionParams.unwrapSecretKey(config, encryptedSecretKeyBytes, oaepPaddingDigestAlgorithmValue);
            return secretKey;
        } catch (EncryptionException e) {
            throw e;
        } catch (Exception e) {
            throw new EncryptionException("Failed to decode and unwrap the provided secret key value!", e);
        }
    }

    public IvParameterSpec getIvSpec() throws EncryptionException {
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

    private static IvParameterSpec generateIv() throws EncryptionException {
        try {
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
            byte[] ivBytes = new byte[16];
            secureRandom.nextBytes(ivBytes);
            return new IvParameterSpec(ivBytes);
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Failed to generate an IV value!", e);
        }
    }

    private static SecretKey generateSecretKey() throws EncryptionException {
        try {
            KeyGenerator generator = KeyGenerator.getInstance(SYMMETRIC_KEY_TYPE, SUN_JCE);
            generator.init(SYMMETRIC_KEY_SIZE);
            return generator.generateKey();
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Failed to generate a secret key!", e);
        }
    }

    protected static byte[] wrapSecretKey(FieldLevelEncryptionConfig config, Key key) throws EncryptionException {
        try {
            Key publicEncryptionKey = config.encryptionCertificate.getPublicKey();
            MGF1ParameterSpec mgf1ParameterSpec = new MGF1ParameterSpec(config.oaepPaddingDigestAlgorithm);
            String asymmetricCipher = ASYMMETRIC_CYPHER.replace("{ALG}", mgf1ParameterSpec.getDigestAlgorithm());
            Cipher cipher = Cipher.getInstance(asymmetricCipher, SUN_JCE);
            cipher.init(Cipher.WRAP_MODE, publicEncryptionKey, getOaepParameterSpec(mgf1ParameterSpec));
            return cipher.wrap(key);
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Failed to wrap secret key!", e);
        }
    }

    protected static Key unwrapSecretKey(FieldLevelEncryptionConfig config, byte[] keyBytes, String oaepDigestAlgorithm) throws EncryptionException {
        if (!oaepDigestAlgorithm.contains("-")) {
            oaepDigestAlgorithm = oaepDigestAlgorithm.replace("SHA", "SHA-");
        }
        try {
            MGF1ParameterSpec mgf1ParameterSpec = new MGF1ParameterSpec(oaepDigestAlgorithm);
            Key key = config.decryptionKey;
            String asymmetricCipher = ASYMMETRIC_CYPHER.replace("{ALG}", mgf1ParameterSpec.getDigestAlgorithm());
            Cipher cipher = Cipher.getInstance(asymmetricCipher, SUN_JCE);
            cipher.init(Cipher.UNWRAP_MODE, key, getOaepParameterSpec(mgf1ParameterSpec));
            return cipher.unwrap(keyBytes, SYMMETRIC_KEY_TYPE, Cipher.SECRET_KEY);
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Failed to unwrap secret key!", e);
        }
    }

    private static OAEPParameterSpec getOaepParameterSpec(MGF1ParameterSpec mgf1ParameterSpec) {
        return new OAEPParameterSpec(mgf1ParameterSpec.getDigestAlgorithm(), "MGF1", mgf1ParameterSpec, PSource.PSpecified.DEFAULT);
    }

    private static String getOrComputeEncryptionCertificateFingerprint(FieldLevelEncryptionConfig config) throws EncryptionException {
        try {
            String providedCertificateFingerprintValue = config.encryptionCertificateFingerprint;
            if (!isNullOrEmpty(providedCertificateFingerprintValue)) {
                return providedCertificateFingerprintValue;
            } else {
                byte[] certificateFingerprintBytes = sha256digestBytes(config.encryptionCertificate.getEncoded());
                return encodeBytes(certificateFingerprintBytes, FieldValueEncoding.HEX);
            }
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Failed to compute encryption certificate fingerprint!", e);
        }
    }

    private static String getOrComputeEncryptionKeyFingerprint(FieldLevelEncryptionConfig config) throws EncryptionException {
        String providedKeyFingerprintValue = config.encryptionKeyFingerprint;
        if (!isNullOrEmpty(providedKeyFingerprintValue)) {
            return providedKeyFingerprintValue;
        } else {
            byte[] keyFingerprintBytes = sha256digestBytes(config.encryptionCertificate.getPublicKey().getEncoded());
            return encodeBytes(keyFingerprintBytes, FieldValueEncoding.HEX);
        }
    }

    private static byte[] sha256digestBytes(byte[] bytes) throws EncryptionException {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(bytes);
            return messageDigest.digest();
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Failed to digest bytes!", e);
        }
    }
}
