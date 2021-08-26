package com.mastercard.developer.interceptors;

import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;
import feign.Response;
import feign.Util;
import feign.codec.DecodeException;
import feign.codec.Decoder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;

import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;

import static com.mastercard.developer.test.TestUtils.assertPayloadEquals;
import static com.mastercard.developer.test.TestUtils.getTestFieldLevelEncryptionConfigBuilder;
import static com.mastercard.developer.utils.FeignUtils.readHeader;
import static org.hamcrest.core.Is.isA;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class OpenFeignFieldLevelEncryptionDecoderTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testDecode_ShouldDecryptResponsePayloadAndUpdateContentLengthHeader() throws Exception {

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
                .withDecryptionPath("$.encryptedData", "$.data")
                .build();

        Type type = mock(Type.class);
        HashMap<String, Collection<String>> headers = new HashMap<String, Collection<String>>() {
            {
                put("content-length", Collections.singleton("100"));
            }
        };
        Response response = Response.builder()
                .status(200)
                .headers(headers)
                .body(encryptedPayload, StandardCharsets.UTF_8)
                .build();
        Decoder delegate = mock(Decoder.class);

        // WHEN
        OpenFeignFieldLevelEncryptionDecoder instanceUnderTest = new OpenFeignFieldLevelEncryptionDecoder(config, delegate);
        instanceUnderTest.decode(response, type);

        // THEN
        ArgumentCaptor<Response> responseCaptor = ArgumentCaptor.forClass(Response.class);
        verify(delegate).decode(responseCaptor.capture(), any(Type.class));
        Response responseValue = responseCaptor.getValue();
        String payload = Util.toString(responseValue.body().asReader());
        assertPayloadEquals("{\"data\":\"string\"}", payload);
        assertEquals(String.valueOf(payload.length()), readHeader(responseValue, "Content-Length"));
    }

    @Test
    public void testDecode_ShouldDoNothing_WhenNoPayload() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder().build();
        Type type = mock(Type.class);
        Response response = mock(Response.class);
        Decoder delegate = mock(Decoder.class);
        when(response.body()).thenReturn(null);

        // WHEN
        OpenFeignFieldLevelEncryptionDecoder instanceUnderTest = new OpenFeignFieldLevelEncryptionDecoder(config, delegate);
        instanceUnderTest.decode(response, type);

        // THEN
        verify(delegate).decode(any(Response.class), any(Type.class));
        verify(response).body();
        verifyNoMoreInteractions(response);
    }

    @Test
    public void testDecode_ShouldDoNothing_WhenEmptyPayload() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder().build();
        Type type = mock(Type.class);
        Response response = mock(Response.class);
        when(response.body()).thenReturn(buildResponseBody(""));
        Decoder delegate = mock(Decoder.class);

        // WHEN
        OpenFeignFieldLevelEncryptionDecoder instanceUnderTest = new OpenFeignFieldLevelEncryptionDecoder(config, delegate);
        instanceUnderTest.decode(response, type);

        // THEN
        verify(delegate).decode(any(Response.class), any(Type.class));
        verify(response).body();
        verifyNoMoreInteractions(response);
    }

    @Test
    public void testDecode_ShouldThrowDecodeException_WhenDecryptionFails() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"a2c494ca28dec4f3d6ce7d68b1044cfe\"," +
                "        \"encryptedKey\": \"NOT A VALID KEY!\"," +
                "        \"encryptedValue\": \"0672589113046bf692265b6ea6088184\"" +
                "    }" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("$.encryptedData", "$.data")
                .build();
        Type type = mock(Type.class);
        Response response = mock(Response.class);
        when(response.body()).thenReturn(buildResponseBody(encryptedPayload));
        Decoder delegate = mock(Decoder.class);

        // THEN
        expectedException.expect(DecodeException.class);
        expectedException.expectMessage("Failed to intercept and decrypt response!");
        expectedException.expectCause(isA(EncryptionException.class));

        // WHEN
        OpenFeignFieldLevelEncryptionDecoder instanceUnderTest = new OpenFeignFieldLevelEncryptionDecoder(config, delegate);
        instanceUnderTest.decode(response, type);
    }

    @Test
    public void testDecode_ShouldDecryptResponsePayloadAndRemoveEncryptionHttpHeaders_WhenRequestedInConfig() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"encryptedValue\": \"21d754bdb4567d35d58720c9f8364075\"" +
                "    }" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("$.encryptedData", "$.data")
                .withIvHeaderName("x-iv")
                .withEncryptedKeyHeaderName("x-encrypted-key")
                .withOaepPaddingDigestAlgorithmHeaderName("x-oaep-padding-digest-algorithm")
                .withEncryptionCertificateFingerprintHeaderName("x-encryption-certificate-fingerprint")
                .withEncryptionKeyFingerprintHeaderName("x-encryption-key-fingerprint")
                .build();

        Type type = mock(Type.class);
        HashMap<String, Collection<String>> headers = new HashMap<String, Collection<String>>() {
            {
                put("content-length", Collections.singleton("100"));
                put("x-iv", Collections.singleton("a32059c51607d0d02e823faecda5fb15"));
                put("x-encrypted-key", Collections.singleton("a31cfe7a7981b72428c013270619554c1d645c04b9d51c7eaf996f55749ef62fd7c7f8d334f95913be41ae38c46d192670fd1acb84ebb85a00cd997f1a9a3f782229c7bf5f0fdf49fe404452d7ed4fd41fbb95b787d25893fbf3d2c75673cecc8799bbe3dd7eb4fe6d3f744b377572cdf8aba1617194e10475b6cd6a8dd4fb8264f8f51534d8f7ac7c10b4ce9c44d15066724b03a0ab0edd512f9e6521fdb5841cd6964e457d6b4a0e45ba4aac4e77d6bbe383d6147e751fa88bc26278bb9690f9ee84b17123b887be2dcef0873f4f9f2c895d90e23456fafb01b99885e31f01a3188f0ad47edf22999cc1d0ddaf49e1407375117b5d66f1f185f2b57078d255"));
                put("x-oaep-padding-digest-algorithm", Collections.singleton("SHA256"));
                put("x-encryption-key-fingerprint", Collections.singleton("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79"));
                put("x-encryption-certificate-fingerprint", Collections.singleton("80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279"));
            }
        };
        Response response = Response.builder()
                .status(200)
                .headers(headers)
                .body(encryptedPayload, StandardCharsets.UTF_8)
                .build();
        Decoder delegate = mock(Decoder.class);

        // WHEN
        OpenFeignFieldLevelEncryptionDecoder instanceUnderTest = new OpenFeignFieldLevelEncryptionDecoder(config, delegate);
        instanceUnderTest.decode(response, type);

        // THEN
        ArgumentCaptor<Response> responseCaptor = ArgumentCaptor.forClass(Response.class);
        verify(delegate).decode(responseCaptor.capture(), any(Type.class));
        Response responseValue = responseCaptor.getValue();
        String payload = Util.toString(responseValue.body().asReader());
        assertPayloadEquals("{\"data\":\"string\"}", payload);
        assertEquals(String.valueOf(payload.length()), readHeader(responseValue, "Content-Length"));
        assertNull(readHeader(responseValue, "x-iv"));
        assertNull(readHeader(responseValue, "x-encrypted-key"));
        assertNull(readHeader(responseValue, "x-oaep-padding-digest-algorithm"));
        assertNull(readHeader(responseValue, "x-encryption-key-fingerprint"));
        assertNull(readHeader(responseValue, "x-encryption-certificate-fingerprint"));
    }

    private static Response.Body buildResponseBody(String payload) {
        Response response = Response.builder()
                .status(200)
                .headers(new HashMap<>())
                .body(payload, StandardCharsets.UTF_8)
                .build();
        return response.body();
    }
}
