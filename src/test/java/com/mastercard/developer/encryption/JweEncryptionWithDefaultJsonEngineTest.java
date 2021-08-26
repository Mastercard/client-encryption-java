package com.mastercard.developer.encryption;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.junit.Test;

import static com.mastercard.developer.test.TestUtils.*;
import static org.junit.Assert.assertNotNull;

public class JweEncryptionWithDefaultJsonEngineTest {

    @Test
    public void testEncryptPayload_ShouldEncryptRootArrays() throws Exception {

        // GIVEN
        String payload = "[" +
                "   {}," +
                "   {}" +
                "]";
        JweConfig config = getTestJweConfigBuilder()
                .withEncryptionPath("$", "$")
                .withDecryptionPath("$.encryptedData", "$")
                .build();

        // WHEN
        String encryptedPayload = JweEncryption.encryptPayload(payload, config);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        assertNotNull(encryptedPayloadObject);
        assertDecryptedJweEquals("[{},{}]", encryptedPayload, config);
    }

    @Test
    public void testDecryptPayload_ShouldDecryptRootArrays() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": \"eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb24vanNvbiIsImVuYyI6IkEyNTZHQ00iLCJhbGciOiJSU0EtT0FFUC0yNTYifQ==.0Gopj6qwiWVd6TnN9mQXgnB2kqYGDg35ByQdWl_gvSVolG3uvNDL_DvFQKRG8l8PmqsmyRwjQ5LzU36w6sNfp4xWsmbEzhYh2CSgnRMHBY902yvR5jbJGMCnwoOKIgAlVpNIbzkT6KX2dc_dvMkDZDVl37NBAxfRFkZl2-TEpKPFJRD7QUPqUMNCNr7aSFnMYMxmDmLKzBj3Q11uMqP8ND-8ySTnzrVezN04zcxsHbgp9PoVNrSwhe0y2O3rwZUQ4N8pkL7J_xNBuc5Cl4aQuiDAV3QPqDkf7jLVaZsp73UPMLPvNZ06J6c_B90yRhaXgXh6E724m5Uriohn0TD_Xg==.5TuQTyNAHCo-X3bOX5n9OQ==.Ve__oxp93w==.WmE4s5ZpP9MLKtGod0QCWg==\"" +
                "}";
        JweConfig config = getTestJweConfigBuilder()
                .withDecryptionPath("$.encryptedData", "$")
                .build();

        // WHEN
        String payload = JweEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        assertPayloadEquals("[{},{}]", payload);
    }
}
