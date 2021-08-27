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
                "    \"encryptedData\": \"eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb24vanNvbiIsImVuYyI6IkEyNTZHQ00iLCJhbGciOiJSU0EtT0FFUC0yNTYifQ.IcTIce59pgtjODJn4PhR7oK3F-gxcd7dishTrT7T9y5VC0U5ZS_JdMoRe59_UTkJMY8Nykb2rv3Oh_jSDYRmGB_CWMIciXYMLHQptLTF5xI1ZauDPnooDMWoOCBD_d3I0wTJNcM7I658rK0ZWSByVK9YqhEo8UaIf4e6egRHQdZ2_IGKgICwmglv_uXQrYewOWFTKR1uMpya1N50MDnWax2NtnW3SljP3mARUBLBnRmOyubQCg-Mgn8fsOWWXm-KL9RrQq9AF_HJceoJl1rRgzPW7g6SLK6EjiGW_ArTmrLaOHg9bYOY_LrbyokK_M1pMo9qup70DHvjHkMZqIL3aQ.vtma3jBIo2STkquxTUX9PQ.9ZoQG0sFvQ.ms4bW3OFd03neRlex-zZ8w\"" +
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
