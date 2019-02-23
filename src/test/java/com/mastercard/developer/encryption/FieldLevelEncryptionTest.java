package com.mastercard.developer.encryption;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import org.apache.commons.codec.binary.Base64;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.spec.MGF1ParameterSpec;

import static com.mastercard.developer.encryption.FieldLevelEncryptionConfig.FieldValueEncoding;
import static com.mastercard.developer.test.TestUtils.getFieldLevelEncryptionConfigBuilder;
import static org.junit.Assert.*;

public class FieldLevelEncryptionTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testEncryptPayload_Nominal() throws Exception {

        // GIVEN
        String payload = "{\"data\": {}, \"encryptedData\": {}}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("data", "encryptedData")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        assertNull(encryptedPayloadObject.get("data"));
        JsonObject encryptedData = (JsonObject) encryptedPayloadObject.get("encryptedData");
        assertNotNull(encryptedData);
        assertEquals("SHA256", encryptedData.get("oaepHashingAlgorithm").getAsString());
        assertEquals("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", encryptedData.get("encryptionKeyFingerprint").getAsString());
        assertEquals("80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279", encryptedData.get("encryptionCertificateFingerprint").getAsString());
        assertNotNull(encryptedData.get("encryptedValue").getAsString());
        assertNotNull(encryptedData.get("encryptedKey").getAsString());
        assertNotNull(encryptedData.get("iv").getAsString());
    }

    @Test
    public void testEncryptPayload_ShouldSupportBase64FieldValueEncoding() throws Exception {

        // GIVEN
        String payload = "{\"data\": {}, \"encryptedData\": {}}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("data", "encryptedData")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .withFieldValueEncoding(FieldValueEncoding.BASE64)
                .withEncryptionCertificateFingerprint(null)
                .withEncryptionKeyFingerprint(null)
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        assertNull(encryptedPayloadObject.get("data"));
        JsonObject encryptedData = (JsonObject) encryptedPayloadObject.get("encryptedData");
        assertNotNull(encryptedData);
        assertEquals("SHA256", encryptedData.get("oaepHashingAlgorithm").getAsString());
        assertEquals("dhsAPB6t46VJDlAA03iHuqXm7A4ibAdwblmUUfwDKnk=", encryptedData.get("encryptionKeyFingerprint").getAsString());
        assertEquals("gIEPwTqDGfzw4uwyLIKkwwS3gsw85nEXY0PP6BYMInk=", encryptedData.get("encryptionCertificateFingerprint").getAsString());
        assertTrue(Base64.isBase64(encryptedData.get("encryptedValue").getAsString()));
        assertTrue(Base64.isBase64(encryptedData.get("encryptedKey").getAsString()));
        assertTrue(Base64.isBase64(encryptedData.get("iv").getAsString()));
    }

    @Test
    public void testEncryptPayload_ShouldEncryptPrimitiveTypes() throws Exception {

        // GIVEN
        String payload = "{\"data\": \"string\", \"encryptedData\": {}}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("data", "encryptedData")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        assertNull(encryptedPayloadObject.get("data"));
        JsonObject encryptedData = (JsonObject) encryptedPayloadObject.get("encryptedData");
        assertNotNull(encryptedData);
    }

    @Test
    public void testEncryptPayload_ShouldDoNothing_WhenInPathDoesNotExistInPayload() throws Exception {

        // GIVEN
        String payload = "{\"data\": {}, \"encryptedData\": {}}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("objectNotInPayload", "encryptedData")
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        assertEquals("{\"data\":{},\"encryptedData\":{}}", encryptedPayload);
    }

    @Test
    public void testEncryptPayload_ShouldCreateEncryptionFields_WhenOutPathParentExistsInPayload() throws Exception {

        // GIVEN
        String payload = "{\"data\": {}, \"encryptedDataParent\": {}}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("data", "encryptedDataParent.encryptedData")
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        assertNull(encryptedPayloadObject.get("data"));
        assertNotNull(encryptedPayloadObject.get("encryptedDataParent").getAsJsonObject().get("encryptedData"));
    }

    @Test
    public void testEncryptPayload_ShouldThrowIllegalArgumentException_WhenOutPathParentDoesNotExistInPayload() throws Exception {

        // GIVEN
        String payload = "{\"data\": {}}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("data", "parentNotInPayload.encryptedData")
                .build();

        // THEN
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Parent path not found in payload: '$['parentNotInPayload']'!");

        // WHEN
        FieldLevelEncryption.encryptPayload(payload, config);
    }

    @Test
    public void testEncryptPayload_ShouldThrowIllegalArgumentException_WhenOutPathIsPathToJsonPrimitive() throws Exception {

        // GIVEN
        String payload = "{\"data\": {}, \"encryptedData\": \"string\"}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("data", "encryptedData")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .build();

        // THEN
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("JSON object expected at path: 'encryptedData'!");

        // WHEN
        FieldLevelEncryption.encryptPayload(payload, config);
    }

    @Test
    public void testEncryptPayload_ShouldComputeCertificateAndKeyFingerprints_WhenFingerprintsNotSetInConfig() throws Exception {

        // GIVEN
        String payload = "{\"data\": {}, \"encryptedData\": {}}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("data", "encryptedData")
                .withEncryptionCertificateFingerprint(null)
                .withEncryptionKeyFingerprint(null)
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        JsonObject encryptedData = (JsonObject) encryptedPayloadObject.get("encryptedData");
        assertEquals("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", encryptedData.get("encryptionKeyFingerprint").getAsString());
        assertEquals("80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279", encryptedData.get("encryptionCertificateFingerprint").getAsString());
    }

    @Test
    public void testEncryptPayload_ShouldNotSetCertificateAndKeyFingerprints_WhenFieldNamesNotSetInConfig() throws Exception {

        // GIVEN
        String payload = "{\"data\": {}, \"encryptedData\": {}}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("data", "encryptedData")
                .withEncryptionCertificateFingerprintFieldName(null)
                .withEncryptionKeyFingerprintFieldName(null)
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        JsonObject encryptedData = (JsonObject) encryptedPayloadObject.get("encryptedData");
        assertNull(encryptedData.get("encryptionKeyFingerprint"));
        assertNull(encryptedData.get("encryptionCertificateFingerprint"));
    }

    @Test
    public void testEncryptPayload_ShouldSupportMultipleEncryptions() throws Exception {

        // GIVEN
        String payload = "{\"data1\": {}, \"data2\": {}, \"encryptedData1\": {}, \"encryptedData2\": {}}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("data1", "encryptedData1")
                .withEncryptionPath("data2", "encryptedData2")
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        assertNull(encryptedPayloadObject.get("data1"));
        assertNull(encryptedPayloadObject.get("data2"));
        JsonElement encryptedData1 = encryptedPayloadObject.get("encryptedData1");
        assertNotNull(encryptedData1.getAsJsonObject().get("encryptedValue"));
        JsonElement encryptedData2 = encryptedPayloadObject.get("encryptedData1");
        assertNotNull(encryptedData2.getAsJsonObject().get("encryptedValue"));
    }

    @Test
    public void testEncryptPayload_ShouldSupportBasicExistingJsonPaths() throws Exception {

        // GIVEN
        String payload = "{\"data1\": {}, \"encryptedData1\": {}," +
                " \"data2\": {}, \"encryptedData2\": {}," +
                " \"data3\": {}, \"encryptedData3\": {}," +
                " \"data4\": { \"object\": {} }, \"encryptedData4\": { \"object\": {} }}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("$.data1", "$.encryptedData1")
                .withEncryptionPath("data2", "encryptedData2")
                .withEncryptionPath("$['data3']", "$['encryptedData3']")
                .withEncryptionPath("$['data4']['object']", "$['encryptedData4']['object']")
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        assertNull(encryptedPayloadObject.get("data1"));
        assertNull(encryptedPayloadObject.get("data2"));
        assertNull(encryptedPayloadObject.get("data3"));
        assertNull(encryptedPayloadObject.get("data4").getAsJsonObject().get("object"));
        assertNotNull(encryptedPayloadObject.get("encryptedData1").getAsJsonObject().get("encryptedValue"));
        assertNotNull(encryptedPayloadObject.get("encryptedData2").getAsJsonObject().get("encryptedValue"));
        assertNotNull(encryptedPayloadObject.get("encryptedData3").getAsJsonObject().get("encryptedValue"));
        assertNotNull(encryptedPayloadObject.get("encryptedData4").getAsJsonObject().get("object").getAsJsonObject().get("encryptedValue"));
    }

    @Test
    public void testEncryptPayload_ShouldSupportBasicNotExistingJsonPaths() throws Exception {

        // GIVEN
        String payload = "{\"data1\": {}, \"data2\": {}, \"data3\": {}, " +
                " \"data4\": { \"object\": {} }, \"encryptedData4\": {}}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("$.data1", "$.encryptedData1")
                .withEncryptionPath("data2", "encryptedData2")
                .withEncryptionPath("$['data3']", "$['encryptedData3']")
                .withEncryptionPath("$['data4']['object']", "$['encryptedData4']['object']")
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        assertNull(encryptedPayloadObject.get("data1"));
        assertNull(encryptedPayloadObject.get("data2"));
        assertNull(encryptedPayloadObject.get("data3"));
        assertNull(encryptedPayloadObject.get("data4").getAsJsonObject().get("object"));
        assertNotNull(encryptedPayloadObject.get("encryptedData1").getAsJsonObject().get("encryptedValue"));
        assertNotNull(encryptedPayloadObject.get("encryptedData2").getAsJsonObject().get("encryptedValue"));
        assertNotNull(encryptedPayloadObject.get("encryptedData3").getAsJsonObject().get("encryptedValue"));
        assertNotNull(encryptedPayloadObject.get("encryptedData4").getAsJsonObject().get("object").getAsJsonObject().get("encryptedValue"));
    }

    @Test
    public void testEncryptPayload_ShouldMergeJsonObjects_WhenOutPathAlreadyContainData() throws Exception {

        // GIVEN
        String payload = "{" +
                "    \"data\": {}," +
                "    \"encryptedData\": {" +
                "        \"field1\": \"field1Value\"," +
                "        \"iv\": \"previousIvValue\"" +
                "    }" +
                "}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("data", "encryptedData")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        JsonObject encryptedData = (JsonObject) encryptedPayloadObject.get("encryptedData");
        assertNotNull(encryptedData);
        assertEquals("field1Value", encryptedData.get("field1").getAsString());
        assertNotEquals("previousIvValue", encryptedData.get("iv").getAsString());
    }

    @Test
    public void testEncryptPayload_ShouldOverwriteInputObject_WhenOutPathSameAsInPath() throws Exception {

        // GIVEN
        String payload = "{" +
                "    \"data\": {" +
                "        \"encryptedData\": {}" +
                "    }   " +
                "}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("data.encryptedData", "data")
                .withEncryptedValueFieldName("encryptedData")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        JsonObject dataObject = (JsonObject) encryptedPayloadObject.get("data");
        JsonPrimitive encryptedDataPrimitive = (JsonPrimitive) dataObject.get("encryptedData");
        assertNotNull(encryptedDataPrimitive);
    }

    @Test
    public void testDecryptPayload_Nominal() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"ba574b07248f63756bce778f8a115819\"," +
                "        \"encryptedKey\": \"26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24\"," +
                "        \"encryptedValue\": \"2867e67545b2f3d0708500a1cea649e3\"," +
                "        \"encryptionCertificateFingerprint\": \"80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279\"," +
                "        \"encryptionKeyFingerprint\": \"761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }" +
                "}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "data")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        JsonObject payloadObject = new Gson().fromJson(payload, JsonObject.class);
        assertNull(payloadObject.get("encryptedData"));
        assertEquals("{}", payloadObject.get("data").toString());
    }

    @Test
    public void testDecryptPayload_ShouldDecryptPrimitiveTypes() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"a2c494ca28dec4f3d6ce7d68b1044cfe\"," +
                "        \"encryptedKey\": \"038c65f154a2b07f6c788aaddc13ecead05fdeb11eca0bf576cab7185df66349d2cba4ba51a5304d45995e915bb1de462f0f66acd05026b21340b567d141653a2175ccfe2030b3b49261c6750381421cf0e29bd67840bcdc8092a44691c6c74dcdf620d5a744832fce3b45b8e3f8ad1af6c919195eb7f878c7435143e328e8b858dd232dbfacf7bb2f73981a80a09dc7c6dcd49ad95df527d415438958700b48994d7f6207f03d974a5cf50181205ac0a301a91e94b35ad162c8cf39475d2505d8ae7b1d4ed6f170091ab523f037a75eddb5ca46db9328c10395b69f8b798c280fa0e76f8385a64fe37b67e8578f3f9572dfb87d71e80a97323753030966901b\"," +
                "        \"encryptedValue\": \"0672589113046bf692265b6ea6088184\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }" +
                "}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "data")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        JsonObject payloadObject = new Gson().fromJson(payload, JsonObject.class);
        assertNull(payloadObject.get("encryptedData"));
        assertEquals("\"string\"", payloadObject.get("data").toString());
    }

    @Test
    public void testDecryptPayload_ShouldSupportBase64FieldValueDecoding() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"uldLBySPY3VrznePihFYGQ==\"," +
                "        \"encryptedKey\": \"Jmh/bQPScUVFHSC9qinMGZ4lM7uetzUXcuMdEpC5g4C0Pb9HuaM3zC7K/509n7RTBZUPEzgsWtgi7m33nhpXsUo8WMcQkBIZlKn3ce+WRyZpZxcYtVoPqNn3benhcv7cq7yH1ktamUiZ5Dq7Ga+oQCaQEsOXtbGNS6vA5Bwa1pjbmMiRIbvlstInz8XTw8h/T0yLBLUJ0yYZmzmt+9i8qL8KFQ/PPDe5cXOCr1Aq2NTSixe5F2K/EI00q6D7QMpBDC7K6zDWgAOvINzifZ0DTkxVe4EE6F+FneDrcJsj+ZeIabrlRcfxtiFziH6unnXktta0sB1xcszIxXdMDbUcJA==\"," +
                "        \"encryptedValue\": \"KGfmdUWy89BwhQChzqZJ4w==\"," +
                "        \"encryptionCertificateFingerprint\": \"gIEPwTqDGfzw4uwyLIKkwwS3gsw85nEXY0PP6BYMInk=\"," +
                "        \"encryptionKeyFingerprint\": \"dhsAPB6t46VJDlAA03iHuqXm7A4ibAdwblmUUfwDKnk=\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }" +
                "}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "data")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .withFieldValueEncoding(FieldValueEncoding.BASE64)
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        JsonObject payloadObject = new Gson().fromJson(payload, JsonObject.class);
        assertNull(payloadObject.get("encryptedData"));
        assertEquals("{}", payloadObject.get("data").toString());
    }

    @Test
    public void testDecryptPayload_ShouldDoNothing_WhenInPathDoesNotExistInPayload() throws Exception {

        // GIVEN
        String encryptedPayload = "{\"data\": {}}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("objectNotInPayload", "data")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        assertEquals("{\"data\":{}}", payload);
    }

    @Test
    public void testDecryptPayload_ShouldCreateDataFields_WhenOutPathParentExistsInPayload() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"ba574b07248f63756bce778f8a115819\"," +
                "        \"encryptedKey\": \"26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24\"," +
                "        \"encryptedValue\": \"2867e67545b2f3d0708500a1cea649e3\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }, " +
                "    \"dataParent\": {}" +
                "}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "dataParent.data")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        JsonObject payloadObject = new Gson().fromJson(payload, JsonObject.class);
        assertNull(payloadObject.get("encryptedData"));
        assertEquals("{}", payloadObject.get("dataParent").getAsJsonObject().get("data").toString());
    }

    @Test
    public void testDecryptPayload_ShouldThrowIllegalArgumentException_WhenOutPathParentDoesNotExistInPayload() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"ba574b07248f63756bce778f8a115819\"," +
                "        \"encryptedKey\": \"26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24\"," +
                "        \"encryptedValue\": \"2867e67545b2f3d0708500a1cea649e3\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }" +
                "}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "parentNotInPayload.data")
                .build();

        // THEN
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Parent path not found in payload: '$['parentNotInPayload']'!");

        // WHEN
        FieldLevelEncryption.decryptPayload(encryptedPayload, config);
    }

    @Test
    public void testDecryptPayload_ShouldThrowIllegalArgumentException_WhenOutPathIsPathToJsonPrimitive() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"ba574b07248f63756bce778f8a115819\"," +
                "        \"encryptedKey\": \"26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24\"," +
                "        \"encryptedValue\": \"2867e67545b2f3d0708500a1cea649e3\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }, " +
                "    \"data\": \"string\"" +
                "}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "data")
                .build();

        // THEN
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("JSON object expected at path: 'data'!");

        // WHEN
        FieldLevelEncryption.decryptPayload(encryptedPayload, config);
    }

    @Test
    public void testDecryptPayload_ShouldThrowIllegalArgumentException_WhenInPathIsPathToJsonPrimitive() throws Exception {

        // GIVEN
        String encryptedPayload = "{ \"encryptedData\": \"string\" }";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "data")
                .build();

        // THEN
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("JSON object expected at path: 'encryptedData'!");

        // WHEN
        FieldLevelEncryption.decryptPayload(encryptedPayload, config);
    }

    @Test
    public void testDecryptPayload_ShouldUseOaepDigestAlgorithmFromConfig_WhenOaepDigestAlgorithmNotReturnedInPayload() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"ba574b07248f63756bce778f8a115819\"," +
                "        \"encryptedKey\": \"26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24\"," +
                "        \"encryptedValue\": \"2867e67545b2f3d0708500a1cea649e3\"" +
                "    }" +
                "}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "data")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        JsonObject payloadObject = new Gson().fromJson(payload, JsonObject.class);
        assertNull(payloadObject.get("encryptedData"));
        assertEquals("{}", payloadObject.get("data").toString());
    }

    @Test
    public void testDecryptPayload_ShouldSupportMultipleDecryptions() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData2\": {" +
                "        \"iv\": \"c1ffb457798714b679e5b59e5b8fb62c\"," +
                "        \"encryptedKey\": \"f16425f1550c28515bc83e25f7f63ca8102a2cbbadd6452c610f03d920563856f1a7318d98bc0939a3a6a84922caebc3691b34aa96ed4d2d016727a30d3622966dec3cb13f9da9d149106afc2b81846e624aa6134551bca169fa539df4034b48e47923cb4f2636b993c805b851cc046a7e98a70ff1c6b43207ac8dcbfbf6132a070860040093d4399af70b0d45cf44854390df9c24f2eb17aa6e745da1a2b7a765f8b4970f6764731d6a7d51af85be669e35ad433ff0942710764265253c956797cd1e3c8ba705ee8578373a14bbab368426d3797bd68076f6ec9c4ef8d43c2959f4fd4c17897a9d6d0622ffc662d5f5c304fb6d5ca84de63f7cf9b9dfe700d2\"," +
                "        \"encryptedValue\": \"a49dff0a6f9ca58bdd3e991f13eb8e53\"" +
                "    }," +
                "    \"encryptedData1\": {" +
                "        \"iv\": \"4c278e7b0c0890973077960f682181b6\"," +
                "        \"encryptedKey\": \"c2c4a40433e91d1175ba933ddb7eb014e9839e3bf639c6c4e2ea532373f146ee6a88515103cb7aeb9df328c67b747c231bfdf4a6b3d366792b6e9ec0f106447f28518a864cc9dd59ed6e1a9ed017229166f23389b4c141b4492981e51ad6863ed48e8c93394378a8e8ab922b8c96dfdf6c683c334eef4c668d9f059b6ac6c26a7d623032ef0bac0e3d4fde5a735d4c09879364efb723c2f2bd3288f8619f9f1a63ed1e283ae7cb40726632fe271fea08252991a158bce3aeca90a4ce7b6895f7b94516ada042de80942ddbc3462baeee49c4169c18c0024fec48743610281cec0333906953da783b3bcd246226efccff4cdefa62c26753db228e0120feff2bdc\"," +
                "        \"encryptedValue\": \"1ea73031bc0cf9c67b61bc1684d78f2b\"" +
                "    }" +
                "}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData1", "data1")
                .withDecryptionPath("encryptedData2", "data2")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        JsonObject payloadObject = new Gson().fromJson(payload, JsonObject.class);
        assertNull(payloadObject.get("encryptedData1"));
        assertNull(payloadObject.get("encryptedData2"));
        assertNotNull(payloadObject.get("data1"));
        assertNotNull(payloadObject.get("data2"));
    }

    @Test
    public void testDecryptPayload_ShouldMergeJsonObjects_WhenOutPathAlreadyContainData() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"17492f69d92d2008ee9289cf3e07bd36\"," +
                "        \"encryptedKey\": \"22b3df5e70777cef394c39ac74bacfcdbfc8cef4a4da771f1d07611f18b4dc9eacde7297870acb421abe77b8b974f53b2e5b834a68e11a4ddab53ece2d37ae7dee5646dc3f4c5c17166906258615b9c7c52f7242a1afa6edf24815c3dbec4b2092a027de11bcdab4c47de0159ce76d2449394f962a07196a5a5b41678a085d77730baee0d3d0e486eb4719aae8f1f1c0fd7026aea7b0872c049e8df1e7eed088fa84fc613602e989fa4e7a7b77ac40da212a462ae5d3df5078be96fcf3d0fe612e0ec401d27a243c0df1feb8241d49248697db5ec79571b9d52386064ee3db11d200156bfd3af03a289ea37ec2c8f315840e7804669a855bf9e34190e3b14d28\"," +
                "        \"encryptedValue\": \"9cad34c0d7b2443f07bb7b7e19817ade132ba3f312b1176c09a312e5b5f908198e1e0cfac0fd8c9f66c70a9b05b1a701\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }, " +
                "    \"data\": {" +
                "        \"field1\": \"previousField1Value\"," +
                "        \"field3\": \"field3Value\"" +
                "    }" +
                "}";

        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "data")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        JsonObject payloadObject = new Gson().fromJson(payload, JsonObject.class);
        assertNull(payloadObject.get("encryptedData"));
        assertEquals("{\"field3\":\"field3Value\",\"field1\":\"field1Value\",\"field2\":\"field2Value\"}", payloadObject.get("data").toString());
    }

    @Test
    public void testDecryptPayload_ShouldKeepInputObject_WhenContainsAdditionalFields() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"ba574b07248f63756bce778f8a115819\"," +
                "        \"encryptedKey\": \"26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24\"," +
                "        \"encryptedValue\": \"2867e67545b2f3d0708500a1cea649e3\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"," +
                "        \"field\": \"fieldValue\"" +
                "    }" +
                "}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "data")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        JsonObject payloadObject = new Gson().fromJson(payload, JsonObject.class);
        assertEquals("\"fieldValue\"", payloadObject.get("encryptedData").getAsJsonObject().get("field").toString());
    }

    @Test
    public void testDecryptPayload_ShouldOverwriteInputObject_WhenOutPathSameAsInPath() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"17492f69d92d2008ee9289cf3e07bd36\"," +
                "        \"encryptedKey\": \"22b3df5e70777cef394c39ac74bacfcdbfc8cef4a4da771f1d07611f18b4dc9eacde7297870acb421abe77b8b974f53b2e5b834a68e11a4ddab53ece2d37ae7dee5646dc3f4c5c17166906258615b9c7c52f7242a1afa6edf24815c3dbec4b2092a027de11bcdab4c47de0159ce76d2449394f962a07196a5a5b41678a085d77730baee0d3d0e486eb4719aae8f1f1c0fd7026aea7b0872c049e8df1e7eed088fa84fc613602e989fa4e7a7b77ac40da212a462ae5d3df5078be96fcf3d0fe612e0ec401d27a243c0df1feb8241d49248697db5ec79571b9d52386064ee3db11d200156bfd3af03a289ea37ec2c8f315840e7804669a855bf9e34190e3b14d28\"," +
                "        \"encryptedValue\": \"9cad34c0d7b2443f07bb7b7e19817ade132ba3f312b1176c09a312e5b5f908198e1e0cfac0fd8c9f66c70a9b05b1a701\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    } " +
                "}";
        FieldLevelEncryptionConfig config = getFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "encryptedData")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        JsonObject payloadObject = new Gson().fromJson(payload, JsonObject.class);
        assertEquals("\"field1Value\"", payloadObject.get("encryptedData").getAsJsonObject().get("field1").toString());
        assertEquals("\"field2Value\"", payloadObject.get("encryptedData").getAsJsonObject().get("field2").toString());
    }
}
