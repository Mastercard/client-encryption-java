package com.mastercard.developer.interceptor;

import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;
import com.mastercard.developer.interceptors.FeignFieldLevelEncryptionDecoder;
import feign.Response;
import feign.Util;
import feign.codec.DecodeException;
import feign.codec.Decoder;
import org.junit.Assert;
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
import static org.hamcrest.core.Is.isA;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class FeignFieldLevelEncryptionDecoderTest {

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
        HashMap<String, Collection<String>> headers = new HashMap<>();
        headers.put("content-length", Collections.singleton("100"));
        Response response = Response.builder()
                .status(200)
                .headers(headers)
                .body(encryptedPayload, StandardCharsets.UTF_8)
                .build();
        Decoder delegate = mock(Decoder.class);

        // WHEN
        FeignFieldLevelEncryptionDecoder instanceUnderTest = new FeignFieldLevelEncryptionDecoder(config, delegate);
        instanceUnderTest.decode(response, type);

        // THEN
        ArgumentCaptor<Response> responseCaptor = ArgumentCaptor.forClass(Response.class);
        verify(delegate).decode(responseCaptor.capture(), any(Type.class));
        Response responseValue = responseCaptor.getValue();
        String payload = Util.toString(responseValue.body().asReader());
        assertPayloadEquals("{\"data\":\"string\"}", payload);
        Assert.assertEquals(String.valueOf(payload.length()), responseValue.headers().get("Content-Length").toArray()[0]);
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
        FeignFieldLevelEncryptionDecoder instanceUnderTest = new FeignFieldLevelEncryptionDecoder(config, delegate);
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
        FeignFieldLevelEncryptionDecoder instanceUnderTest = new FeignFieldLevelEncryptionDecoder(config, delegate);
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
        expectedException.expectMessage("Failed to decrypt response!");
        expectedException.expectCause(isA(EncryptionException.class));

        // WHEN
        FeignFieldLevelEncryptionDecoder instanceUnderTest = new FeignFieldLevelEncryptionDecoder(config, delegate);
        instanceUnderTest.decode(response, type);
    }

    private static Response.Body buildResponseBody(String payload) {
        Response response = Response.builder()
                .status(200)
                .headers(new HashMap<String, Collection<String>>())
                .body(payload, StandardCharsets.UTF_8)
                .build();
        return response.body();
    }
}
