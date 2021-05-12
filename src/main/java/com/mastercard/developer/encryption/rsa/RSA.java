package com.mastercard.developer.encryption.rsa;

import com.mastercard.developer.encryption.EncryptionException;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;

public class RSA {

    private RSA() {
        // Nothing to do here
    }

    private static final String ASYMMETRIC_CYPHER = "RSA/ECB/OAEPWith{ALG}AndMGF1Padding";
    private static final String SYMMETRIC_KEY_TYPE = "AES";

    public static byte[] wrapSecretKey(PublicKey publicKey, Key privateKey, String oaepDigestAlgorithm) throws EncryptionException {
        try {
            MGF1ParameterSpec mgf1ParameterSpec = new MGF1ParameterSpec(oaepDigestAlgorithm);
            String asymmetricCipher = ASYMMETRIC_CYPHER.replace("{ALG}", mgf1ParameterSpec.getDigestAlgorithm());
            Cipher cipher = Cipher.getInstance(asymmetricCipher);
            cipher.init(Cipher.WRAP_MODE, publicKey, getOaepParameterSpec(mgf1ParameterSpec));
            return cipher.wrap(privateKey);
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Failed to wrap secret key!", e);
        }
    }

    public static Key unwrapSecretKey(PrivateKey decryptionKey, byte[] keyBytes, String oaepDigestAlgorithm) throws EncryptionException {
        if (!oaepDigestAlgorithm.contains("-")) {
            oaepDigestAlgorithm = oaepDigestAlgorithm.replace("SHA", "SHA-");
        }
        try {
            MGF1ParameterSpec mgf1ParameterSpec = new MGF1ParameterSpec(oaepDigestAlgorithm);
            String asymmetricCipher = ASYMMETRIC_CYPHER.replace("{ALG}", mgf1ParameterSpec.getDigestAlgorithm());
            Cipher cipher = Cipher.getInstance(asymmetricCipher);
            cipher.init(Cipher.UNWRAP_MODE, decryptionKey, getOaepParameterSpec(mgf1ParameterSpec));
            return cipher.unwrap(keyBytes, SYMMETRIC_KEY_TYPE, Cipher.SECRET_KEY);
        } catch (GeneralSecurityException e) {
            throw new EncryptionException("Failed to unwrap secret key!", e);
        }
    }

    private static OAEPParameterSpec getOaepParameterSpec(MGF1ParameterSpec mgf1ParameterSpec) {
        return new OAEPParameterSpec(mgf1ParameterSpec.getDigestAlgorithm(), "MGF1", mgf1ParameterSpec, PSource.PSpecified.DEFAULT);
    }
}
