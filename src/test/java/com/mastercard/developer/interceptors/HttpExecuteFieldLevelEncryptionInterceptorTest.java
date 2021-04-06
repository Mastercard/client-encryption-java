package com.mastercard.developer.interceptors;

import com.google.api.client.http.*;
import com.mastercard.developer.encryption.EncryptionConfig;
import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;
import com.mastercard.developer.test.TestUtils;
import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

import static com.mastercard.developer.test.TestUtils.assertPayloadEquals;
import static com.mastercard.developer.test.TestUtils.getTestFieldLevelEncryptionConfigBuilder;
import static org.hamcrest.core.Is.isA;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class HttpExecuteFieldLevelEncryptionInterceptorTest {

    private static final String JSON_TYPE = "application/json; charset=utf-8";

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testFrom_ShouldReturnTheCorrectInterceptor() throws Exception {
        // GIVEN
        EncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .build();

        HttpExecuteEncryptionInterceptor interceptor = HttpExecuteEncryptionInterceptor.from(config);
        assertTrue(interceptor instanceof HttpExecuteFieldLevelEncryptionInterceptor);
    }

    @Test
    public void testIntercept_ShouldEncryptRequestPayloadAndUpdateContentLengthHeader() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("$.foo", "$.encryptedFoo")
                .build();
        HttpRequest request = mock(HttpRequest.class);
        HttpHeaders httpHeaders = new HttpHeaders();
        when(request.getContent()).thenReturn(new ByteArrayContent(JSON_TYPE, "{\"foo\":\"bar\"}".getBytes()));
        when(request.getHeaders()).thenReturn(httpHeaders);

        // WHEN
        HttpExecuteFieldLevelEncryptionInterceptor instanceUnderTest = new HttpExecuteFieldLevelEncryptionInterceptor(config);
        instanceUnderTest.intercept(request);

        // THEN
        ArgumentCaptor<HttpContent> contentCaptor = ArgumentCaptor.forClass(HttpContent.class);
        verify(request).setContent(contentCaptor.capture());
        ByteArrayOutputStream encryptedPayloadStream = new ByteArrayOutputStream();
        contentCaptor.getValue().writeTo(encryptedPayloadStream);
        String encryptedPayload = encryptedPayloadStream.toString(StandardCharsets.UTF_8.name());
        Assert.assertFalse(encryptedPayload.contains("foo"));
        Assert.assertTrue(encryptedPayload.contains("encryptedFoo"));
        assertEquals(encryptedPayload.length(), httpHeaders.getContentLength().intValue());
    }

    @Test
    public void testIntercept_ShouldDoNothing_WhenNoPayload() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("$.foo", "$.encryptedFoo")
                .build();
        HttpRequest request = mock(HttpRequest.class);
        when(request.getContent()).thenReturn(null);

        // WHEN
        HttpExecuteFieldLevelEncryptionInterceptor instanceUnderTest = new HttpExecuteFieldLevelEncryptionInterceptor(config);
        instanceUnderTest.intercept(request);

        // THEN
        verify(request).getContent();
        verifyNoMoreInteractions(request);
    }

    @Test
    public void testIntercept_ShouldThrowIOException_WhenEncryptionFails() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("$.foo", "$.encryptedFoo")
                .withEncryptionCertificate(TestUtils.getTestInvalidEncryptionCertificate()) // Invalid certificate
                .build();
        HttpRequest request = mock(HttpRequest.class);
        when(request.getContent()).thenReturn(new ByteArrayContent(JSON_TYPE, "{\"foo\":\"bar\"}".getBytes()));

        // THEN
        expectedException.expect(IOException.class);
        expectedException.expectMessage("Failed to intercept and encrypt request!");
        expectedException.expectCause(isA(EncryptionException.class));

        // WHEN
        HttpExecuteFieldLevelEncryptionInterceptor instanceUnderTest = new HttpExecuteFieldLevelEncryptionInterceptor(config);
        instanceUnderTest.intercept(request);
    }

    @Test
    public void testInterceptResponse_ShouldDecryptResponsePayloadAndUpdateContentLengthHeader() throws Exception {

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
        HttpResponse response = mock(HttpResponse.class);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setContentLength(100L);
        when(response.parseAsString()).thenReturn(encryptedPayload);
        when(response.getHeaders()).thenReturn(httpHeaders);

        // WHEN
        HttpExecuteFieldLevelEncryptionInterceptor instanceUnderTest = new HttpExecuteFieldLevelEncryptionInterceptor(config);
        instanceUnderTest.interceptResponse(response);

        // THEN
        Field contentField = response.getClass().getDeclaredField("content");
        contentField.setAccessible(true);
        InputStream payloadInputStream = (InputStream) contentField.get(response);
        String payload = IOUtils.toString(payloadInputStream, StandardCharsets.UTF_8);
        assertPayloadEquals("{\"data\":\"string\"}", payload);
        assertEquals(payload.length(), httpHeaders.getContentLength().intValue());
    }

    @Test
    public void testInterceptResponse_ShouldDoNothing_WhenNoPayload() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder().build();
        HttpResponse response = mock(HttpResponse.class);
        when(response.parseAsString()).thenReturn(null);

        // WHEN
        HttpExecuteFieldLevelEncryptionInterceptor instanceUnderTest = new HttpExecuteFieldLevelEncryptionInterceptor(config);
        instanceUnderTest.interceptResponse(response);

        // THEN
        verify(response).parseAsString();
        verifyNoMoreInteractions(response);
    }

    @Test
    public void testInterceptResponse_ShouldThrowIOException_WhenDecryptionFails() throws Exception {

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
        HttpResponse response = mock(HttpResponse.class);
        when(response.parseAsString()).thenReturn(encryptedPayload);

        // THEN
        expectedException.expect(IOException.class);
        expectedException.expectMessage("Failed to intercept and decrypt response!");
        expectedException.expectCause(isA(EncryptionException.class));

        // WHEN
        HttpExecuteFieldLevelEncryptionInterceptor instanceUnderTest = new HttpExecuteFieldLevelEncryptionInterceptor(config);
        instanceUnderTest.interceptResponse(response);
    }

    @Test
    public void testIntercept_ShouldEncryptRequestPayloadAndAddEncryptionHttpHeaders_WhenRequestedInConfig() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("$.foo", "$.encryptedFoo")
                .withIvHeaderName("x-iv")
                .withEncryptedKeyHeaderName("x-encrypted-key")
                .withOaepPaddingDigestAlgorithmHeaderName("x-oaep-padding-digest-algorithm")
                .withEncryptionCertificateFingerprintHeaderName("x-encryption-certificate-fingerprint")
                .withEncryptionKeyFingerprintHeaderName("x-encryption-key-fingerprint")
                .build();
        HttpRequest request = mock(HttpRequest.class);
        HttpHeaders httpHeaders = new HttpHeaders();
        when(request.getContent()).thenReturn(new ByteArrayContent(JSON_TYPE, "{\"foo\":\"bar\"}".getBytes()));
        when(request.getHeaders()).thenReturn(httpHeaders);

        // WHEN
        HttpExecuteFieldLevelEncryptionInterceptor instanceUnderTest = new HttpExecuteFieldLevelEncryptionInterceptor(config);
        instanceUnderTest.intercept(request);

        // THEN
        ArgumentCaptor<HttpContent> contentCaptor = ArgumentCaptor.forClass(HttpContent.class);
        verify(request).setContent(contentCaptor.capture());
        ByteArrayOutputStream encryptedPayloadStream = new ByteArrayOutputStream();
        contentCaptor.getValue().writeTo(encryptedPayloadStream);
        String encryptedPayload = encryptedPayloadStream.toString(StandardCharsets.UTF_8.name());
        Assert.assertFalse(encryptedPayload.contains("foo"));
        Assert.assertTrue(encryptedPayload.contains("encryptedFoo"));
        assertEquals(encryptedPayload.length(), httpHeaders.getContentLength().intValue());
        assertNotNull(httpHeaders.get("x-iv"));
        assertNotNull(httpHeaders.get("x-encrypted-key"));
        assertEquals("SHA256", httpHeaders.get("x-oaep-padding-digest-algorithm"));
        assertEquals("80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279", httpHeaders.get("x-encryption-certificate-fingerprint"));
        assertEquals("761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79", httpHeaders.get("x-encryption-key-fingerprint"));
    }

    @Test
    public void testInterceptResponse_ShouldDecryptResponsePayloadAndRemoveEncryptionHttpHeaders_WhenRequestedInConfig() throws Exception {

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

        HttpResponse response = mock(HttpResponse.class);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.set("x-iv", "a32059c51607d0d02e823faecda5fb15");
        httpHeaders.set("x-encrypted-key", "a31cfe7a7981b72428c013270619554c1d645c04b9d51c7eaf996f55749ef62fd7c7f8d334f95913be41ae38c46d192670fd1acb84ebb85a00cd997f1a9a3f782229c7bf5f0fdf49fe404452d7ed4fd41fbb95b787d25893fbf3d2c75673cecc8799bbe3dd7eb4fe6d3f744b377572cdf8aba1617194e10475b6cd6a8dd4fb8264f8f51534d8f7ac7c10b4ce9c44d15066724b03a0ab0edd512f9e6521fdb5841cd6964e457d6b4a0e45ba4aac4e77d6bbe383d6147e751fa88bc26278bb9690f9ee84b17123b887be2dcef0873f4f9f2c895d90e23456fafb01b99885e31f01a3188f0ad47edf22999cc1d0ddaf49e1407375117b5d66f1f185f2b57078d255");
        httpHeaders.set("x-oaep-padding-digest-algorithm", "SHA256");
        httpHeaders.set("x-encryption-key-fingerprint", "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79");
        httpHeaders.set("x-encryption-certificate-fingerprint", "80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279");
        httpHeaders.setContentLength(100L);
        when(response.parseAsString()).thenReturn(encryptedPayload);
        when(response.getHeaders()).thenReturn(httpHeaders);

        // WHEN
        HttpExecuteFieldLevelEncryptionInterceptor instanceUnderTest = new HttpExecuteFieldLevelEncryptionInterceptor(config);
        instanceUnderTest.interceptResponse(response);

        // THEN
        Field contentField = response.getClass().getDeclaredField("content");
        contentField.setAccessible(true);
        InputStream payloadInputStream = (InputStream) contentField.get(response);
        String payload = IOUtils.toString(payloadInputStream, StandardCharsets.UTF_8);
        assertPayloadEquals("{\"data\":\"string\"}", payload);
        assertEquals(payload.length(), httpHeaders.getContentLength().intValue());
        assertNull(response.getHeaders().get("x-iv"));
        assertNull(response.getHeaders().get("x-encrypted-key"));
        assertNull(response.getHeaders().get("x-oaep-padding-digest-algorithm"));
        assertNull(response.getHeaders().get("x-encryption-key-fingerprint"));
        assertNull(response.getHeaders().get("x-encryption-certificate-fingerprint"));
    }
}
