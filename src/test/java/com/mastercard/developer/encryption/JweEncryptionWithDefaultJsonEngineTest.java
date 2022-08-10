package com.mastercard.developer.encryption;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.junit.Test;
import org.junit.jupiter.api.Assertions;

import static com.mastercard.developer.test.TestUtils.*;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

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
    public void testEncryptPayload_ShouldEncryptWithWildcard() throws Exception {

        // GIVEN
        String payload = "{ \"fields\": [" +
                "   {" +
                "      \"field1\": \"AAAA\"," +
                "      \"field2\": \"asdf\"" +
                "   }," +
                "   {" +
                "      \"field1\": \"BBBB\"," +
                "      \"field2\": \"zxcv\"" +
                "   }" +
                "]}";
        JweConfig config = getTestJweConfigBuilder()
                .withEncryptionPath("$.fields[*]field1", "$.fields[*]")
                .withDecryptionPath("$.fields[*]encryptedData", "$.fields[*]field1")
                .build();

        // WHEN
        String encryptedPayload = JweEncryption.encryptPayload(payload, config);

        // THEN
        assertDecryptedJweEquals("{\"fields\":[{\"field2\":\"asdf\",\"field1\":\"AAAA\"},{\"field2\":\"zxcv\",\"field1\":\"BBBB\"}]}", encryptedPayload, config);
    }

    @Test
    public void testEncryptPayload_ShouldCreateEncryptedValue_WhenOutPathParentDoesNotExistInPayload() throws Exception {

        // GIVEN
        String payload = "{\"data\": {}}";
        JweConfig config = getTestJweConfigBuilder()
                .withEncryptionPath("$", "$.encryptedDataParent")
                .build();

        // WHEN
        String encryptedPayload = JweEncryption.encryptPayload(payload, config);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        assertNull(encryptedPayloadObject.get("data"));
        Assertions.assertNotNull(encryptedPayloadObject.get("encryptedDataParent").getAsJsonObject().get("encryptedData"));
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

    @Test
    public void testDecryptPayload_ShouldSupportPayloadWithEncryptedValueParent() throws Exception {

        // GIVEN
        String encryptedPayload = "{\n" +
                "    \"encryptedDataParent\": {\n" +
                "        \"encryptedData\": \"eyJraWQiOiI3NjFiMDAzYzFlYWRlM2E1NDkwZTUwMDBkMzc4ODdiYWE1ZTZlYzBlMjI2YzA3NzA2ZTU5OTQ1MWZjMDMyYTc5IiwiY3R5IjoiYXBwbGljYXRpb24vanNvbiIsImVuYyI6IkEyNTZHQ00iLCJhbGciOiJSU0EtT0FFUC0yNTYifQ.XVy1AR51sUvwT-AtcsogQDo_klFi1EMYW8Wz7qM0e1dA3jNX5nTa38JhRcVuyVK15OenTYfg7aaH_fLjPZI1Mukd0BBnTuonh8T9CX5tbAAYx_KGPxc7a7ekBO-xXEA762eRvIIQJDZgQ_C3U39kc-XoaxC-ZYx8Va_aPBsXI1uozAfj3j5XVDnSmGAVWc2N4STTlCKbL4EO6YXASl_PrAOIVVSUrhpYvNS7GnjrP9x49tlRmTS0Dx-_MhkIAJM6H25YAuUmO-LW3gikReOUgGeY9_JtOioDs2J4ncKqugPFKr8kYF1cKnMwFv0TS9p5qR0kiF20bxRMvhbazf_Q5Q.V2Uz5-YRNq9ZIJjhRsKYIw.jB1s8rczGEj2OjU.qs4zVUf2tHML02Rglq5ncw\"\n" +
                "    }\n" +
                "}";
        JweConfig config = getTestJweConfigBuilder()
                .withDecryptionPath("$.encryptedDataParent.encryptedData", "$")
                .build();

        // WHEN
        String payload = JweEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        assertPayloadEquals("{\"data\": {}}", payload);
    }
}
