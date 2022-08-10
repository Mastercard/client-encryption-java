package com.mastercard.developer.encryption;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.mastercard.developer.encryption.aes.AESCBC;
import com.mastercard.developer.test.TestUtils;
import com.mastercard.developer.utils.EncryptionUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.rules.ExpectedException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;

import static com.mastercard.developer.encryption.FieldLevelEncryptionConfig.FieldValueEncoding;
import static com.mastercard.developer.encryption.FieldLevelEncryptionParams.SYMMETRIC_KEY_TYPE;
import static com.mastercard.developer.test.TestUtils.*;
import static com.mastercard.developer.utils.EncodingUtils.base64Decode;
import static com.mastercard.developer.utils.EncryptionUtils.loadDecryptionKey;
import static org.hamcrest.core.Is.isA;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.*;

public class FieldLevelEncryptionWithDefaultJsonEngineTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testEncryptBytes_InteroperabilityTest() throws Exception {

        // GIVEN
        String ivValue = "VNm/scgd1jhWF0z4+Qh6MA==";
        String keyValue = "mZzmzoURXI3Vk0vdsPkcFw==";
        String dataValue = "some data ù€@";
        IvParameterSpec ivParameterSpec = new IvParameterSpec(base64Decode(ivValue));
        byte[] keyBytes = base64Decode(keyValue);
        SecretKey symmetricKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, SYMMETRIC_KEY_TYPE);

        // WHEN
        byte[] encryptedBytes = AESCBC.cipher(symmetricKey, ivParameterSpec, dataValue.getBytes(), Cipher.ENCRYPT_MODE);

        // THEN
        byte[] expectedEncryptedBytes = base64Decode("Y6X9YneTS4VuPETceBmvclrDoCqYyBgZgJUdnlZ8/0g=");
        assertArrayEquals(expectedEncryptedBytes, encryptedBytes);
    }

    @Test
    public void testDecryptBytes_InteroperabilityTest() throws Exception {

        // GIVEN
        String ivValue = "VNm/scgd1jhWF0z4+Qh6MA==";
        String keyValue = "mZzmzoURXI3Vk0vdsPkcFw==";
        String encryptedDataValue = "Y6X9YneTS4VuPETceBmvclrDoCqYyBgZgJUdnlZ8/0g=";
        IvParameterSpec ivParameterSpec = new IvParameterSpec(base64Decode(ivValue));
        byte[] keyBytes = base64Decode(keyValue);
        SecretKey symmetricKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, SYMMETRIC_KEY_TYPE);

        // WHEN
        byte[] decryptedBytes = AESCBC.cipher(symmetricKey, ivParameterSpec, base64Decode(encryptedDataValue), Cipher.DECRYPT_MODE);

        // THEN
        byte[] expectedBytes = "some data ù€@".getBytes();
        assertArrayEquals(expectedBytes, decryptedBytes);
    }

    @Test
    public void testDecryptPayload_InteroperabilityTest() throws Exception {

        // GIVEN
        String encryptedPayload = "{\"data\":\"WtBPYHL5jdU/BsECYzlyRUPIElWCwSCgKhk5RPy2AMZBGmC8OUJ1L9HC/SF2QpCU+ucZTmo7XOjhSdVi0/yrdZP1OG7dVWcW4MEWpxiU1gl0fS0LKKPOFjEymSP5f5otdTFCp00xPfzp+l6K3S3kZTAuSG1gh6TaRL+qfC1POz8KxhCEL8D1MDvxnlmchPx/hEyAzav0AID3T7T4WomzUXErNrnbDCCiL6pm4IBR8cDAzU4eSmTxdzZFyvTpBQDXVyFdkaNTo3GXk837wujVK8EX3c+gsJvMq4XVJFwGmPNhPM6P7OmdK45cldWrD5j2gO2VBH5aW1EXfot7d11bjJC9T8D/ZOQFF6uLIG7J9x9R0Ts0zXD/H24y9/jF30rKKX7TNmKHn5uh1Czd+h7ryIAqaQsOu6ILBKfH7W/NIR5qYN1GiL/kOYwx2pdIGQdcdolVdxV8Z6bt4Tcvq3jSZaCbhJI/kphZL7QHJgcG6luz9k0457x/0QCDPlve6JNgUQzAOYC64X0a07JpERH0O08/YbntKEq6qf7UhloyI5A=\"}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionKey(EncryptionUtils.loadDecryptionKey("./src/test/resources/keys/pkcs1/test_key_pkcs1-2048.pem"))
                .withDecryptionPath("$", "$")
                .withEncryptedValueFieldName("data")
                .withFieldValueEncoding(FieldValueEncoding.BASE64)
                .build();
        String oaepPaddingDigest = "SHA256";
        String encryptedKey = "dobCRy+NUxdQdN0oMLT4dXUzQ+We7BahMfJunoAmwwUpk9jJrW66BASPalS2QWChPaKDM4Ft/BeNsu0wBoUZ0hHIT9ftx5g4tY6Xu2iLRiFWFDCHYOSdL+yVv98FcM6fxc34FNyg3/rOPWeyS3Q9YAOgcqiCwWYu4kqa34tNWCW1vnTmtz+dCKiiCZo/uHUkCtoAI5fEe+inHHToZL+LFlQ2Xd0u/nsu5Ep14Il5mTv8FyfLgwRgfilcqy4t2Kh3bpZ46LllO36DHXtQoI1e0ayMFfKTO87++NWxYNOilrverJ01WHnA+PyXhg4XU3RlU0CVWBN06fKbHBDH6GCmOA==";
        String iv = "+yBXlo+gYGe2q0xzLDLLzQ==";

        // WHEN
        FieldLevelEncryptionParams params = new FieldLevelEncryptionParams(iv, encryptedKey, oaepPaddingDigest, config);
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config, params);

        // THEN
        assertTrue(payload.contains("account"));
    }

    @Test
    public void testEncryptPayload_Nominal() throws Exception {

        // GIVEN
        String payload = "{" +
                "    \"data\": {" +
                "        \"field1\": \"value1\"," +
                "        \"field2\": \"value2\"" +
                "    }," +
                "    \"encryptedData\": {}" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("data", "encryptedData")
                .withDecryptionPath("encryptedData", "data")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        assertNull(encryptedPayloadObject.get("data"));
        JsonObject encryptedData = (JsonObject) encryptedPayloadObject.get("encryptedData");
        assertNotNull(encryptedData);
        assertEquals(6, encryptedData.entrySet().size());
        assertEquals("SHA256", encryptedData.get("oaepHashingAlgorithm").getAsString());
        assertEquals("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", encryptedData.get("encryptionKeyFingerprint").getAsString());
        assertEquals("80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279", encryptedData.get("encryptionCertificateFingerprint").getAsString());
        assertNotNull(encryptedData.get("encryptedValue").getAsString());
        assertNotNull(encryptedData.get("encryptedKey").getAsString());
        assertNotNull(encryptedData.get("iv").getAsString());
        assertDecryptedPayloadEquals("{\"data\":{\"field1\":\"value1\",\"field2\":\"value2\"}}", encryptedPayload, config);
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
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("$.fields[*]field1", "$.fields[*]encryptedData")
                .withDecryptionPath("$.fields[*]encryptedData", "$.fields[*]field1")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        assertDecryptedPayloadEquals("{\"fields\":[{\"field2\":\"asdf\",\"field1\":\"AAAA\"},{\"field2\":\"zxcv\",\"field1\":\"BBBB\"}]}", encryptedPayload, config);
    }


    @Test
    public void testEncryptPayload_ShouldSupportBase64FieldValueEncoding() throws Exception {

        // GIVEN
        String payload = "{\"data\": {}, \"encryptedData\": {}}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
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
        assertEquals("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", encryptedData.get("encryptionKeyFingerprint").getAsString());
        assertEquals("80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279", encryptedData.get("encryptionCertificateFingerprint").getAsString());
        assertEquals(16, base64Decode(encryptedData.get("encryptedValue").getAsString()).length);
        assertEquals(256, base64Decode(encryptedData.get("encryptedKey").getAsString()).length);
        assertEquals(16, base64Decode(encryptedData.get("iv").getAsString()).length);
    }

    @ParameterizedTest
    @ValueSource(strings = {"\"string\"", "false", "1984"})
    void testEncryptPayload_ShouldEncryptPrimitiveTypes(String data) throws Exception {

        // GIVEN
        String payload = String.format("{\"data\": %s, \"encryptedData\": {}}", data);
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("data", "encryptedData")
                .withDecryptionPath("encryptedData", "data")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        assertNull(encryptedPayloadObject.get("data"));
        assertNotNull(encryptedPayloadObject.get("encryptedData"));
        assertDecryptedPayloadEquals(String.format("{\"data\":%s}", data), encryptedPayload, config);
    }

    @Test
    public void testEncryptPayload_ShouldEncryptArrayFields() throws Exception {

        // GIVEN
        String payload = "{" +
                "    \"items\": [" +
                "        {}," +
                "        {}" +
                "    ]" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("items", "encryptedItems")
                .withDecryptionPath("encryptedItems", "items")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        assertNull(encryptedPayloadObject.get("items"));
        assertNotNull(encryptedPayloadObject.get("encryptedItems"));
        assertDecryptedPayloadEquals("{\"items\":[{},{}]}", encryptedPayload, config);
    }

    @Test
    public void testEncryptPayload_ShouldEncryptRootArrays() throws Exception {

        // GIVEN
        String payload = "[" +
                "   {}," +
                "   {}" +
                "]";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("$", "$")
                .withDecryptionPath("$", "$")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        assertNotNull(encryptedPayloadObject);
        assertDecryptedPayloadEquals("[{},{}]", encryptedPayload, config);
    }

    @Test
    public void testEncryptPayload_ShouldDoNothing_WhenInPathDoesNotExistInPayload() throws Exception {

        // GIVEN
        String payload = "{\"data\": {}, \"encryptedData\": {}}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("objectNotInPayload", "encryptedData")
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        assertPayloadEquals("{\"data\":{},\"encryptedData\":{}}", encryptedPayload);
    }

    @Test
    public void testEncryptPayload_ShouldCreateEncryptionFields_WhenOutPathParentExistsInPayload() throws Exception {

        // GIVEN
        String payload = "{\"data\": {}, \"encryptedDataParent\": {}}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
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
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
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
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
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
    public void testEncryptPayload_ShouldNotSetCertificateAndKeyFingerprints_WhenFieldNamesNotSetInConfig() throws Exception {

        // GIVEN
        String payload = "{\"data\": {}, \"encryptedData\": {}}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
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
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
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
        JsonElement encryptedData2 = encryptedPayloadObject.get("encryptedData2");
        assertNotNull(encryptedData2.getAsJsonObject().get("encryptedValue"));
        // The 2 should use a different set of params (IV and symmetric key)
        String iv1 = encryptedData1.getAsJsonObject().get("iv").getAsString();
        String iv2 = encryptedData2.getAsJsonObject().get("iv").getAsString();
        assertNotEquals(iv1, iv2);
    }

    @Test
    public void testEncryptPayload_ShouldSupportBasicExistingJsonPaths() throws Exception {

        // GIVEN
        String payload = "{\"data1\": {}, \"encryptedData1\": {}," +
                " \"data2\": {}, \"encryptedData2\": {}," +
                " \"data3\": {}, \"encryptedData3\": {}," +
                " \"data4\": { \"object\": {} }, \"encryptedData4\": { \"object\": {} }}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
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
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
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
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
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
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("data.encryptedData", "data")
                .withEncryptedValueFieldName("encryptedData")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        JsonObject dataObject = (JsonObject) encryptedPayloadObject.get("data");
        assertNotNull(dataObject.get("iv"));
        assertNotNull(dataObject.get("encryptedKey"));
        assertNotNull(dataObject.get("encryptionCertificateFingerprint"));
        assertNotNull(dataObject.get("encryptionKeyFingerprint"));
        assertNotNull(dataObject.get("oaepHashingAlgorithm"));
        assertNotNull(dataObject.get("encryptedData"));
    }

    @Test
    public void testEncryptPayload_ShouldNotAddOaepPaddingDigestAlgorithm_WhenOaepPaddingDigestAlgorithmFieldNameNotSet() throws Exception {

        // GIVEN
        String payload = "{\"data\": {}, \"encryptedData\": {}}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("data", "encryptedData")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .withOaepPaddingDigestAlgorithmFieldName(null)
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        JsonObject encryptedData = (JsonObject) encryptedPayloadObject.get("encryptedData");
        assertNotNull(encryptedData);
        assertEquals(5, encryptedData.entrySet().size());
    }

    @Test
    public void testEncryptPayload_ShouldSupportRootAsInputPath() throws Exception {

        // GIVEN
        String payload = "{" +
                "    \"field1\": \"value1\"," +
                "    \"field2\": \"value2\"" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("$", "encryptedData")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        assertNull(encryptedPayloadObject.get("field1"));
        assertNull(encryptedPayloadObject.get("field2"));
        JsonObject encryptedData = (JsonObject) encryptedPayloadObject.get("encryptedData");
        assertNotNull(encryptedData);
        assertEquals(6, encryptedData.entrySet().size());
    }

    @Test
    public void testEncryptPayload_ShouldSupportRootAsInputPathAndOutputPath() throws Exception {

        // GIVEN
        String payload = "{" +
                "    \"field1\": \"value1\"," +
                "    \"field2\": \"value2\"" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("$", "$")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        assertNull(encryptedPayloadObject.get("field1"));
        assertNull(encryptedPayloadObject.get("field2"));
        assertEquals(6, encryptedPayloadObject.entrySet().size());
    }

    @Test
    public void testEncryptPayload_ShouldThrowEncryptionException_WhenEncryptionErrorOccurs() throws Exception {

        // GIVEN
        String payload = "{\"data\": {}, \"encryptedData\": {}}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("data", "encryptedData")
                .withEncryptionCertificate(TestUtils.getTestInvalidEncryptionCertificate()) // Invalid certificate
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .build();

        // THEN
        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage("Failed to wrap secret key!");
        expectedException.expectCause(isA(InvalidKeyException.class));

        // WHEN
        FieldLevelEncryption.encryptPayload(payload, config);
    }

    @Test
    public void testEncryptPayload_ShouldUseProvidedEncryptionParams_WhenPassedAsArgument() throws Exception {

        // GIVEN
        String payload = "{\"data\": {}, \"encryptedData\": {}}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("data", "encryptedData")
                .build();
        FieldLevelEncryptionParams params = FieldLevelEncryptionParams.generate(config);

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config, params);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        JsonObject encryptedData = (JsonObject) encryptedPayloadObject.get("encryptedData");
        assertEquals(params.getIvValue(), encryptedData.get("iv").getAsString());
        assertEquals(params.getEncryptedKeyValue(), encryptedData.get("encryptedKey").getAsString());
        assertEquals(params.getOaepPaddingDigestAlgorithmValue(), encryptedData.get("oaepHashingAlgorithm").getAsString());
        assertEquals(config.encryptionCertificateFingerprint, encryptedData.get("encryptionCertificateFingerprint").getAsString());
        assertEquals(config.encryptionKeyFingerprint, encryptedData.get("encryptionKeyFingerprint").getAsString());
    }

    @Test
    public void testEncryptPayload_ShouldGenerateEncryptionParams_WhenNullArgument() throws Exception {

        // GIVEN
        String payload = "{" +
                "    \"data\": {" +
                "        \"field1\": \"value1\"," +
                "        \"field2\": \"value2\"" +
                "    }," +
                "    \"encryptedData\": {}" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("data", "encryptedData")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config, null);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        assertNull(encryptedPayloadObject.get("data"));
        JsonObject encryptedData = (JsonObject) encryptedPayloadObject.get("encryptedData");
        assertNotNull(encryptedData);
        assertEquals(6, encryptedData.entrySet().size());
    }

    @Test
    public void testEncryptPayload_ShouldNotAddEncryptionParamsToPayload_WhenFieldNamesNotSetInConfig() throws Exception {

        // GIVEN
        String payload = "{" +
                "    \"data\": {" +
                "        \"field1\": \"value1\"," +
                "        \"field2\": \"value2\"" +
                "    }," +
                "    \"encryptedData\": {}" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("data", "encryptedData")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                .withOaepPaddingDigestAlgorithmFieldName(null)
                .withEncryptedKeyFieldName(null)
                .withEncryptedKeyHeaderName("x-encrypted-key")
                .withEncryptionKeyFingerprintFieldName(null)
                .withEncryptionCertificateFingerprintFieldName(null)
                .withIvFieldName(null)
                .withIvHeaderName("x-iv")
                .build();

        // WHEN
        String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);

        // THEN
        JsonObject encryptedPayloadObject = new Gson().fromJson(encryptedPayload, JsonObject.class);
        assertNull(encryptedPayloadObject.get("data"));
        JsonObject encryptedData = (JsonObject) encryptedPayloadObject.get("encryptedData");
        assertNotNull(encryptedData);
        assertEquals(1, encryptedData.entrySet().size()); // "encryptedValue" only
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
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "data")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        assertPayloadEquals("{\"data\":{}}", payload);
    }

    @Test
    public void testDecryptPayload_ShouldDecryptPrimitiveTypes_String() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"a32059c51607d0d02e823faecda5fb15\"," +
                "        \"encryptedKey\": \"a31cfe7a7981b72428c013270619554c1d645c04b9d51c7eaf996f55749ef62fd7c7f8d334f95913be41ae38c46d192670fd1acb84ebb85a00cd997f1a9a3f782229c7bf5f0fdf49fe404452d7ed4fd41fbb95b787d25893fbf3d2c75673cecc8799bbe3dd7eb4fe6d3f744b377572cdf8aba1617194e10475b6cd6a8dd4fb8264f8f51534d8f7ac7c10b4ce9c44d15066724b03a0ab0edd512f9e6521fdb5841cd6964e457d6b4a0e45ba4aac4e77d6bbe383d6147e751fa88bc26278bb9690f9ee84b17123b887be2dcef0873f4f9f2c895d90e23456fafb01b99885e31f01a3188f0ad47edf22999cc1d0ddaf49e1407375117b5d66f1f185f2b57078d255\"," +
                "        \"encryptedValue\": \"21d754bdb4567d35d58720c9f8364075\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "data")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        assertPayloadEquals("{\"data\":\"string\"}", payload);
    }

    @Test
    public void testDecryptPayload_ShouldDecryptPrimitiveTypes_Integer() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"5bb681fb4ca4a8f85a9c80b8f234e87c\"," +
                "        \"encryptedKey\": \"d6819275d3a692bddce0baa10187769e0d683c351fb4e1857ab30f2572fbe1db95c34583d20ea5b224a638e99d26f6935104500b49fc1e855b7af30f34ac1d148090c6393e77e0f16d710614d00817ac862f9af730e9b3596d2c0dacf1349abd18717792ac3040f4ef1cc2e8fd9e0d685a192bfc6800e79022393eb3ce326757ba556107be28c02590390fad73117f7da3d96c05f54aaa36541b05680f23a222f1b7bbe54f1b070515dfbea8e5312708d5c27bfe9d9350e7bb72914351a6db1d83cdefee7d7514d04b73b6e285f334b27c674ad50ec830494ebc2901f1fe1738863b2d7940c98a15e1467d501545bffa724fd97b2d673e92629c9be79ca7381f\"," +
                "        \"encryptedValue\": \"072b6ef69afd42d43b89afdf8f8bb172\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "data")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        assertPayloadEquals("{\"data\":1984}", payload);
    }

    @Test
    public void testDecryptPayload_ShouldDecryptPrimitiveTypes_Boolean() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"683c1559d6b9366f21efc4dec682cca2\"," +
                "        \"encryptedKey\": \"631f0729018db2aa4f02823eeac6c1bf4bc766897dfd8159ec831086acb68cf37d91427347db77869fe1088e4cd8553b5bb0308accb43e92a3977245e0005385fc538aacea323cb62d44d21c932b7fbb3fc2039de44d18fff130108b30bd5c9925a3463ace729099ce63375dfa1dd9ec9f1e277de6b4ace5161a0e47ae81908aa2f8b44a654be2b863d6dfc5112a422dda065d8fbc0d5e47ea435409262c608edfc28a49e90fbda035c1743ec8cabd453d75775b0ab7b660b20b3a1f37c6eecffa32a26b07adf78432e1dd479a2ce19002846cb2fa2488ade423265ce7c4b003373837971c7b803925624f8eeb9254dad347941ebab8f641522b5b1efe53f572\"," +
                "        \"encryptedValue\": \"cc8bb0cc778d508f198c39364cce9137\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "data")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        assertPayloadEquals("{\"data\":false}", payload);
    }

    @Test
    public void testDecryptPayload_ShouldDecryptArrayFields() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedItems\": {" +
                "        \"iv\": \"34010a3ea7231126a0d1e088ec8db173\"," +
                "        \"encryptedKey\": \"072aee9f7dd6cf381eb61e6d93c2e19e4032e1166d36d3ccb32ec379815f472e27d82a0de48617ff440d37a534bb38b170cf236a78148a375971e83b087eb7d05807863e70b43baa446934fe6f70150e3ca4e49e70fecabb1969c1fc5a38f13a75e318077760e4fe53e25ca011781d1038d19bb3a16928d35302bc7e389c8fb089230b8c0acc3c7e59c120cfe3aece6ff346aaa598a2baf003026f0a32307af022b9515fea564bb5d491b0159b20d909deb9cb5e8077d6471ad1ad3d7e743d6c3cf09f999c22006038980268b9d0cac1fd2e53b1a6e8e4d63b0a3e4457ff27ffab7cd025011b678e0ff56537c29e81ed087fe11988c2c92a7c7695f1fc6f856a\"," +
                "        \"encryptedValue\": \"d91268566c92621d394b5e5d94069387\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("$.encryptedItems", "$.items")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        assertPayloadEquals("{\"items\":[{},{}]}", payload);
    }

    @Test
    public void testDecryptPayload_ShouldDecryptRootArrays() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "  \"encryptedValue\": \"3496b0c505bcea6a849f8e30b553e6d4\"," +
                "  \"iv\": \"ed82c0496e9d5ac769d77bdb2eb27958\"," +
                "  \"encryptedKey\": \"29ea447b70bdf85dd509b5d4a23dc0ffb29fd1acf50ed0800ec189fbcf1fb813fa075952c3de2915d63ab42f16be2ed46dc27ba289d692778a1d585b589039ba0b25bad326d699c45f6d3cffd77b5ec37fe12e2c5456d49980b2ccf16402e83a8e9765b9b93ca37d4d5181ec3e5327fd58387bc539238f1c20a8bc9f4174f5d032982a59726b3e0b9cf6011d4d7bfc3afaf617e768dea6762750bce07339e3e55fdbd1a1cd12ee6bbfbc3c7a2d7f4e1313410eb0dad13e594a50a842ee1b2d0ff59d641987c417deaa151d679bc892e5c051b48781dbdefe74a12eb2b604b981e0be32ab81d01797117a24fbf6544850eed9b4aefad0eea7b3f5747b20f65d3f\"," +
                "  \"oaepHashingAlgorithm\": \"SHA256\"" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("$", "$")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        assertPayloadEquals("[{},{}]", payload);
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
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "data")
                .withFieldValueEncoding(FieldValueEncoding.BASE64)
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        assertPayloadEquals("{\"data\":{}}", payload);
    }

    @Test
    public void testDecryptPayload_ShouldDoNothing_WhenInPathDoesNotExistInPayload() throws Exception {

        // GIVEN
        String encryptedPayload = "{\"data\": {}}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("objectNotInPayload", "data")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        assertPayloadEquals("{\"data\":{}}", payload);
    }

    @Test
    public void testDecryptPayload_ShouldDoNothing_WhenEncryptedValueDoesNotExistInPayload() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"ba574b07248f63756bce778f8a115819\"," +
                "        \"encryptedKey\": \"26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "data")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        JsonObject payloadObject = new Gson().fromJson(payload, JsonObject.class);
        assertNotNull(payloadObject.get("encryptedData"));
        assertNotNull(payloadObject.get("encryptedData").getAsJsonObject().get("iv"));
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
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "dataParent.data")
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
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
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
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
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
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
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
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "data")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        assertPayloadEquals("{\"data\":{}}", payload);
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
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
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

        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "data")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        JsonObject payloadObject = new Gson().fromJson(payload, JsonObject.class);
        assertNull(payloadObject.get("encryptedData"));
        JsonElement dataObject = payloadObject.get("data");
        assertNotNull(dataObject);
        assertEquals("field1Value", dataObject.getAsJsonObject().get("field1").getAsString());
        assertEquals("field2Value", dataObject.getAsJsonObject().get("field2").getAsString());
        assertEquals("field3Value", dataObject.getAsJsonObject().get("field3").getAsString());
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
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "data")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        JsonObject payloadObject = new Gson().fromJson(payload, JsonObject.class);
        assertEquals("\"fieldValue\"", payloadObject.get("encryptedData").getAsJsonObject().get("field").toString());
    }

    @Test
    public void testDecryptPayload_ShouldOverwriteInputObject_WhenOutPathSameAsInPath_ObjectData() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"17492f69d92d2008ee9289cf3e07bd36\"," +
                "        \"encryptedKey\": \"22b3df5e70777cef394c39ac74bacfcdbfc8cef4a4da771f1d07611f18b4dc9eacde7297870acb421abe77b8b974f53b2e5b834a68e11a4ddab53ece2d37ae7dee5646dc3f4c5c17166906258615b9c7c52f7242a1afa6edf24815c3dbec4b2092a027de11bcdab4c47de0159ce76d2449394f962a07196a5a5b41678a085d77730baee0d3d0e486eb4719aae8f1f1c0fd7026aea7b0872c049e8df1e7eed088fa84fc613602e989fa4e7a7b77ac40da212a462ae5d3df5078be96fcf3d0fe612e0ec401d27a243c0df1feb8241d49248697db5ec79571b9d52386064ee3db11d200156bfd3af03a289ea37ec2c8f315840e7804669a855bf9e34190e3b14d28\"," +
                "        \"encryptedValue\": \"9cad34c0d7b2443f07bb7b7e19817ade132ba3f312b1176c09a312e5b5f908198e1e0cfac0fd8c9f66c70a9b05b1a701\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    } " +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
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

    /**
     * https://github.com/Mastercard/client-encryption-java/issues/3
     */
    @Test
    public void testDecryptPayload_ShouldOverwriteInputObject_WhenOutPathSameAsInPath_PrimitiveTypeData() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"data\": {" +
                "        \"encryptedValue\": \"e2d6a3a76ea6e605e55b400e5a4eba11\"," +
                "        \"iv\": \"3ce861359fa1630c7a794901ee14bf41\"," +
                "        \"encryptedKey\": \"02bb8d5c7d113ef271f199c09f0d76db2b6d5d2d209ad1a20dbc4dd0d04576a92ceb917eea5f403ccf64c3c39dda564046909af96c82fad62f89c3cbbec880ea3105a0a171af904cd3b86ea68991202a2795dca07050ca58252701b7ecea06055fd43e96f4beee48b6275e86af93c88c21994ff46f0610171bd388a2c0a1f518ffc8346f7f513f3283feae5b102c8596ddcb2aea5e62ceb17222e646c599f258463405d28ac012bfd4cc431f94111ee07d79e660948485e38c13cdb8bba8e1df3f7dba0f4c77696f71930533c955f3a430658edaa03b0b0c393934d60f5ac3ea5c06ed64bf969fc01942eac432b8e0c56f7538659a72859d445d150c169ae690\"," +
                "        \"encryptionCertificateFingerprint\": \"80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279\"," +
                "        \"encryptionKeyFingerprint\": \"761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }" +
                "}";

        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("$.data", "$.data")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        JsonObject payloadObject = new Gson().fromJson(payload, JsonObject.class);
        assertEquals("string", payloadObject.get("data").getAsString());
    }

    @Test
    public void testDecryptPayload_ShouldSupportRootAsInputPath() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"iv\": \"6fef040c8fe8ad9ec56b74efa194b5f7\"," +
                "    \"encryptedKey\": \"b04c69e1ca944fd7641ea79f03e5cd540144759212fa50d07c8a97ab30ca8bded324e2d4b8cd2613b25cd6bceac35b76c2fa1b521ff205b5f33eafaf4102efbefd35cae6707f985953d6dac366cca36295b29d8af3d94d5d5d1532158066b9fecfc2cc000f10e4757967e84c043d7db164d7488f5bef28f59c989c4cd316c870da7b7c1d10cfd73b6d285cd43447e9e96702e3e818011b45b0ecda21b02286db04b7c77ab193dcc4a9036beff065a404689b7cea40b6a348554900ae3eb819af9cb53ab800e158051aac8d8075045a06808e3730cd8cbc1b5334dcdc922d0227f6da1518442914ac5f3abf6751dfb5721074459d0626b62e934f6a6e6fd96020\"," +
                "    \"encryptedValue\": \"386cdb354a33a5b5ae44fa73622297d0372857d1f7634b45010f691964958e2afca0f7391742dc1243768ccf0b4fce8b\"," +
                "    \"encryptionCertificateFingerprint\": \"80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279\"," +
                "    \"encryptionKeyFingerprint\": \"761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79\"," +
                "    \"oaepHashingAlgorithm\": \"SHA256\"" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("$", "$.encryptedData")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        JsonObject payloadObject = new Gson().fromJson(payload, JsonObject.class);
        assertNull(payloadObject.get("iv"));
        assertNull(payloadObject.get("encryptedKey"));
        assertNull(payloadObject.get("encryptedValue"));
        assertNull(payloadObject.get("oaepHashingAlgorithm"));
        assertNull(payloadObject.get("encryptionCertificateFingerprint"));
        assertNull(payloadObject.get("encryptionKeyFingerprint"));
        assertEquals("\"value1\"", payloadObject.get("encryptedData").getAsJsonObject().get("field1").toString());
        assertEquals("\"value2\"", payloadObject.get("encryptedData").getAsJsonObject().get("field2").toString());
    }

    @Test
    public void testDecryptPayload_ShouldSupportRootAsInputPathAndOutputPath() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"iv\": \"6fef040c8fe8ad9ec56b74efa194b5f7\"," +
                "    \"encryptedKey\": \"b04c69e1ca944fd7641ea79f03e5cd540144759212fa50d07c8a97ab30ca8bded324e2d4b8cd2613b25cd6bceac35b76c2fa1b521ff205b5f33eafaf4102efbefd35cae6707f985953d6dac366cca36295b29d8af3d94d5d5d1532158066b9fecfc2cc000f10e4757967e84c043d7db164d7488f5bef28f59c989c4cd316c870da7b7c1d10cfd73b6d285cd43447e9e96702e3e818011b45b0ecda21b02286db04b7c77ab193dcc4a9036beff065a404689b7cea40b6a348554900ae3eb819af9cb53ab800e158051aac8d8075045a06808e3730cd8cbc1b5334dcdc922d0227f6da1518442914ac5f3abf6751dfb5721074459d0626b62e934f6a6e6fd96020\"," +
                "    \"encryptedValue\": \"386cdb354a33a5b5ae44fa73622297d0372857d1f7634b45010f691964958e2afca0f7391742dc1243768ccf0b4fce8b\"," +
                "    \"encryptionCertificateFingerprint\": \"80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279\"," +
                "    \"encryptionKeyFingerprint\": \"761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79\"," +
                "    \"oaepHashingAlgorithm\": \"SHA256\"" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("$", "$")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        assertPayloadEquals("{\"field1\":\"value1\",\"field2\":\"value2\"}", payload);
    }

    @Test
    public void testDecryptPayload_ShouldSupportRootAsOutputPath() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"6fef040c8fe8ad9ec56b74efa194b5f7\"," +
                "        \"encryptedKey\": \"b04c69e1ca944fd7641ea79f03e5cd540144759212fa50d07c8a97ab30ca8bded324e2d4b8cd2613b25cd6bceac35b76c2fa1b521ff205b5f33eafaf4102efbefd35cae6707f985953d6dac366cca36295b29d8af3d94d5d5d1532158066b9fecfc2cc000f10e4757967e84c043d7db164d7488f5bef28f59c989c4cd316c870da7b7c1d10cfd73b6d285cd43447e9e96702e3e818011b45b0ecda21b02286db04b7c77ab193dcc4a9036beff065a404689b7cea40b6a348554900ae3eb819af9cb53ab800e158051aac8d8075045a06808e3730cd8cbc1b5334dcdc922d0227f6da1518442914ac5f3abf6751dfb5721074459d0626b62e934f6a6e6fd96020\"," +
                "        \"encryptedValue\": \"386cdb354a33a5b5ae44fa73622297d0372857d1f7634b45010f691964958e2afca0f7391742dc1243768ccf0b4fce8b\"," +
                "        \"encryptionCertificateFingerprint\": \"80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279\"," +
                "        \"encryptionKeyFingerprint\": \"761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("$.encryptedData", "$")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        assertPayloadEquals("{\"field1\":\"value1\",\"field2\":\"value2\"}", payload);
    }

    @Test
    public void testDecryptPayload_ShouldThrowEncryptionException_WhenDecryptionErrorOccurs() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"ba574b07248f63756bce778f8a115819\"," +
                "        \"encryptedKey\": \"26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24\"," +
                "        \"encryptedValue\": \"2867e67545b2f3d0708500a1cea649e3\"" +
                "    }" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "data")
                .withOaepPaddingDigestAlgorithm("SHA-256")
                // Not the right key
                .withDecryptionKey(loadDecryptionKey("./src/test/resources/keys/pkcs12/test_key.p12", "mykeyalias", "Password1"))
                .build();

        // THEN
        expectedException.expect(EncryptionException.class);
        expectedException.expectMessage("Failed to unwrap secret key!");
        expectedException.expectCause(isA(InvalidKeyException.class));

        // WHEN
        FieldLevelEncryption.decryptPayload(encryptedPayload, config);
    }

    @Test
    public void testDecryptPayload_ShouldKeepCertificateAndKeyFingerprints_WhenFieldNamesNotSetInConfig() throws Exception {

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
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "data")
                .withEncryptionCertificateFingerprintFieldName(null)
                .withEncryptionKeyFingerprintFieldName(null)
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config);

        // THEN
        JsonObject payloadObject = new Gson().fromJson(payload, JsonObject.class);
        JsonElement encryptedDataObject = payloadObject.get("encryptedData");
        assertNotNull(encryptedDataObject);
        assertNotNull(encryptedDataObject.getAsJsonObject().get("encryptionCertificateFingerprint"));
        assertNotNull(encryptedDataObject.getAsJsonObject().get("encryptionKeyFingerprint"));
        assertEquals("{}", payloadObject.get("data").toString());
    }

    @Test
    public void testDecryptPayload_ShouldUseProvidedEncryptionParams_WhenPassedAsArgument() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"encryptedValue\": \"2867e67545b2f3d0708500a1cea649e3\"" +
                "    }" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "data")
                .build();

        String ivValue = "ba574b07248f63756bce778f8a115819";
        String encryptedKeyValue = "26687f6d03d27145451d20bdaa29cc199e2533bb9eb7351772e31d1290b98380b43dbf47b9a337cc2ecaff9d3d9fb45305950f13382c5ad822ee6df79e1a57b14a3c58c71090121994a9f771ef96472669671718b55a0fa8d9f76de9e172fedcabbc87d64b5a994899e43abb19afa840269012c397b5b18d4babc0e41c1ad698db98c89121bbe5b2d227cfc5d3c3c87f4f4c8b04b509d326199b39adfbd8bca8bf0a150fcf3c37b9717382af502ad8d4d28b17b91762bf108d34aba0fb40ca410c2ecaeb30d68003af20dce27d9d034e4c557b8104e85f859de0eb709b23f9978869bae545c7f1b62173887eae9e75e4b6d6b4b01d7172ccc8c5774c0db51c24";
        String oaepHashingAlgorithmValue = "SHA256";
        FieldLevelEncryptionParams params = new FieldLevelEncryptionParams(ivValue, encryptedKeyValue, oaepHashingAlgorithmValue, config);

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config, params);

        // THEN
        assertPayloadEquals("{\"data\":{}}", payload);
    }

    @Test
    public void testDecryptPayload_ShouldUseEncryptionParamsFromPayload_WhenNullArgument() throws Exception {

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
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "data")
                .build();

        // WHEN
        String payload = FieldLevelEncryption.decryptPayload(encryptedPayload, config, null);

        // THEN
        assertPayloadEquals("{\"data\":{}}", payload);
    }

    @Test
    public void testDecryptPayload_ShouldThrowIllegalStateException_WhenEncryptionParamsAreMissing() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"encryptedValue\": \"2867e67545b2f3d0708500a1cea649e3\"" +
                "    }" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("encryptedData", "data")
                .withEncryptedKeyFieldName(null)
                .withEncryptedKeyHeaderName("x-encrypted-key")
                .withIvFieldName(null)
                .withIvHeaderName("x-iv")
                .build();

        // THEN
        expectedException.expect(IllegalStateException.class);
        expectedException.expectMessage("Encryption params have to be set when not stored in HTTP payloads!");

        // WHEN
        FieldLevelEncryption.decryptPayload(encryptedPayload, config, null);
    }
}
