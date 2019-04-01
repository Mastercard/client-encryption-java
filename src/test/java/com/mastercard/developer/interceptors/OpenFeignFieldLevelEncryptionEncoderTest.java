package com.mastercard.developer.interceptors;

import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;
import com.mastercard.developer.test.TestUtils;
import feign.RequestTemplate;
import feign.codec.EncodeException;
import feign.codec.Encoder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;

import java.lang.reflect.Type;

import static com.mastercard.developer.test.TestUtils.getTestFieldLevelEncryptionConfigBuilder;
import static org.hamcrest.core.Is.isA;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class OpenFeignFieldLevelEncryptionEncoderTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testEncode_ShouldEncryptRequestPayloadAndUpdateContentLengthHeader() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("$.foo", "$.encryptedFoo")
                .build();
        Type type = mock(Type.class);
        Encoder delegate = mock(Encoder.class);
        Object object = mock(Object.class);
        RequestTemplate request = mock(RequestTemplate.class);
        when(request.body()).thenReturn("{\"foo\":\"bar\"}".getBytes());

        // WHEN
        OpenFeignFieldLevelEncryptionEncoder instanceUnderTest = new OpenFeignFieldLevelEncryptionEncoder(config, delegate);
        instanceUnderTest.encode(object, type, request);

        // THEN
        verify(delegate).encode(object, type, request);
        verify(request).body();
        ArgumentCaptor<String> encryptedPayloadCaptor = ArgumentCaptor.forClass(String.class);
        verify(request).body(encryptedPayloadCaptor.capture());
        verify(request).header(eq("Content-Length"), anyString());
        String encryptedPayload = encryptedPayloadCaptor.getValue();
        assertFalse(encryptedPayload.contains("foo"));
        assertTrue(encryptedPayload.contains("encryptedFoo"));
    }

    @Test
    public void testEncode_ShouldDoNothing_WhenNoPayload() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("$.foo", "$.encryptedFoo")
                .build();
        Type type = mock(Type.class);
        Encoder delegate = mock(Encoder.class);
        Object object = mock(Object.class);
        RequestTemplate request = mock(RequestTemplate.class);
        when(request.body()).thenReturn(null);

        // WHEN
        OpenFeignFieldLevelEncryptionEncoder instanceUnderTest = new OpenFeignFieldLevelEncryptionEncoder(config, delegate);
        instanceUnderTest.encode(object, type, request);

        // THEN
        verify(request).body();
        verifyNoMoreInteractions(request);
    }

    @Test
    public void testEncode_ShouldDoNothing_WhenEmptyPayload() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("$.foo", "$.encryptedFoo")
                .build();
        Type type = mock(Type.class);
        Encoder delegate = mock(Encoder.class);
        Object object = mock(Object.class);
        RequestTemplate request = mock(RequestTemplate.class);
        when(request.body()).thenReturn("".getBytes());

        // WHEN
        OpenFeignFieldLevelEncryptionEncoder instanceUnderTest = new OpenFeignFieldLevelEncryptionEncoder(config, delegate);
        instanceUnderTest.encode(object, type, request);

        // THEN
        verify(request).body();
        verifyNoMoreInteractions(request);
    }

    @Test
    public void testEncode_ShouldThrowEncodeException_WhenEncryptionFails() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("$.foo", "$.encryptedFoo")
                .withEncryptionCertificate(TestUtils.getTestInvalidEncryptionCertificate()) // Invalid certificate
                .build();
        Type type = mock(Type.class);
        Encoder delegate = mock(Encoder.class);
        Object object = mock(Object.class);
        RequestTemplate request = mock(RequestTemplate.class);
        when(request.body()).thenReturn("{\"foo\":\"bar\"}".getBytes());

        // THEN
        expectedException.expect(EncodeException.class);
        expectedException.expectMessage("Failed to intercept and encrypt request!");
        expectedException.expectCause(isA(EncryptionException.class));

        // WHEN
        OpenFeignFieldLevelEncryptionEncoder instanceUnderTest = new OpenFeignFieldLevelEncryptionEncoder(config, delegate);
        instanceUnderTest.encode(object, type, request);
    }

    @Test
    public void testEncode_ShouldEncryptRequestPayloadAndAddEncryptionHttpHeaders_WhenRequestedInConfig() throws Exception {

        // GIVEN
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withEncryptionPath("$.foo", "$.encryptedFoo")
                .withIvHeaderName("x-iv")
                .withEncryptedKeyHeaderName("x-encrypted-key")
                .withOaepPaddingDigestAlgorithmHeaderName("x-oaep-padding-digest-algorithm")
                .withEncryptionCertificateFingerprintHeaderName("x-encryption-certificate-fingerprint")
                .withEncryptionKeyFingerprintHeaderName("x-encryption-key-fingerprint")
                .build();
        Type type = mock(Type.class);
        Encoder delegate = mock(Encoder.class);
        Object object = mock(Object.class);
        RequestTemplate request = mock(RequestTemplate.class);
        when(request.body()).thenReturn("{\"foo\":\"bar\"}".getBytes());

        // WHEN
        OpenFeignFieldLevelEncryptionEncoder instanceUnderTest = new OpenFeignFieldLevelEncryptionEncoder(config, delegate);
        instanceUnderTest.encode(object, type, request);

        // THEN
        verify(delegate).encode(object, type, request);
        verify(request).body();
        ArgumentCaptor<String> encryptedPayloadCaptor = ArgumentCaptor.forClass(String.class);
        verify(request).body(encryptedPayloadCaptor.capture());
        verify(request).header(eq("Content-Length"), anyString());
        String encryptedPayload = encryptedPayloadCaptor.getValue();
        assertFalse(encryptedPayload.contains("foo"));
        assertTrue(encryptedPayload.contains("encryptedFoo"));
        verify(request).header(eq("x-iv"), anyString());
        verify(request).header(eq("x-encrypted-key"), anyString());
        verify(request).header("x-oaep-padding-digest-algorithm", "SHA256");
        verify(request).header("x-encryption-certificate-fingerprint", "80810fc13a8319fcf0e2ec322c82a4c304b782cc3ce671176343cfe8160c2279");
        verify(request).header("x-encryption-key-fingerprint", "761b003c1eade3a5490e5000d37887baa5e6ec0e226c07706e599451fc032a79");
    }
}
