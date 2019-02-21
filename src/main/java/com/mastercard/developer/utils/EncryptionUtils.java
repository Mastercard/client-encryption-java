package com.mastercard.developer.utils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Utility class.
 */
public final class EncryptionUtils {

    private EncryptionUtils() {
    }

    /**
     * Populate a X509 encryption certificate object with the certificate data at the given file path.
     */
    public static Certificate loadEncryptionCertificate(String certificatePath)
            throws CertificateException, NoSuchProviderException, FileNotFoundException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509", "SUN");
        return factory.generateCertificate(new FileInputStream(certificatePath));
    }

    /**
     * Load a PKCS#8 formatted RSA decryption key from a file.
     */
    public static PrivateKey loadDecryptionKey(String pkcs8KeyFilePath)
            throws NoSuchProviderException, NoSuchAlgorithmException, IOException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(pkcs8KeyFilePath));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SunRsaSign");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        try {
            return keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("Unexpected key format, try: " +
                    "'openssl pkcs8 -topk8 -inform PEM -outform DER -in your_key.pem -out your_key.der -nocrypt'!", e);
        }
    }
}
