package com.mastercard.developer.utils;

import org.junit.Assert;
import org.junit.Test;

import java.security.PrivateKey;
import java.security.cert.Certificate;

public class EncryptionUtilsTest {

    @Test
    public void testLoadEncryptionCertificate_Nominal() throws Exception {

        // GIVEN
        String certificatePath = "./src/test/resources/test_certificate.cert";

        // WHEN
        Certificate certificate = EncryptionUtils.loadEncryptionCertificate(certificatePath);

        // THEN
        Assert.assertNotNull(certificate);
        Assert.assertEquals("X.509", certificate.getType());
    }

    @Test
    public void testLoadDecryptionKey_NominalDer() throws Exception {

        // GIVEN
        String keyPath = "./src/test/resources/test_key.der";

        // WHEN
        PrivateKey privateKey = EncryptionUtils.loadDecryptionKey(keyPath);

        // THEN
        Assert.assertNotNull(privateKey);
        Assert.assertEquals("PKCS#8", privateKey.getFormat());
    }

    @Test(expected = IllegalArgumentException.class) // THEN
    public void testLoadDecryptionKey_ShouldThrowIllegalArgumentException_WhenPemEncodedKey() throws Exception {

        // GIVEN
        String keyPath = "./src/test/resources/test_key.pem";

        // WHEN
        EncryptionUtils.loadDecryptionKey(keyPath);
    }

    @Test
    public void testLoadDecryptionKey_NominalPkcs12() throws Exception {

        // GIVEN
        String keyContainerPath = "./src/test/resources/test_key_container.p12";
        String keyAlias = "mykeyalias";
        String keyPassword = "Password1";

        // WHEN
        PrivateKey privateKey = EncryptionUtils.loadDecryptionKey(keyContainerPath, keyAlias, keyPassword);

        // THEN
        Assert.assertNotNull(privateKey.getEncoded());
        Assert.assertEquals("PKCS#8", privateKey.getFormat());
    }
}
