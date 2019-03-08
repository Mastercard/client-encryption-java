package com.mastercard.developer.interceptor;

import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;
import com.mastercard.developer.interceptors.FeignFieldLevelEncryptionEncoder;
import com.mastercard.developer.test.TestUtils;
import feign.RequestTemplate;
import feign.codec.EncodeException;
import feign.codec.Encoder;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;

import java.lang.reflect.Type;

import static com.mastercard.developer.test.TestUtils.getTestFieldLevelEncryptionConfigBuilder;
import static org.hamcrest.core.Is.isA;
import static org.mockito.Mockito.*;

public class FeignFieldLevelEncryptionEncoderTest {

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
        FeignFieldLevelEncryptionEncoder instanceUnderTest = new FeignFieldLevelEncryptionEncoder(config, delegate);
        instanceUnderTest.encode(object, type, request);

        // THEN
        verify(delegate).encode(object, type, request);
        verify(request).body();
        ArgumentCaptor<String> encryptedPayloadCaptor = ArgumentCaptor.forClass(String.class);
        verify(request).body(encryptedPayloadCaptor.capture());
        verify(request).header(eq("Content-Length"), anyString());
        String encryptedPayload = encryptedPayloadCaptor.getValue();
        Assert.assertFalse(encryptedPayload.contains("foo"));
        Assert.assertTrue(encryptedPayload.contains("encryptedFoo"));
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
        FeignFieldLevelEncryptionEncoder instanceUnderTest = new FeignFieldLevelEncryptionEncoder(config, delegate);
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
        FeignFieldLevelEncryptionEncoder instanceUnderTest = new FeignFieldLevelEncryptionEncoder(config, delegate);
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
        expectedException.expectMessage("Failed to encrypt request!");
        expectedException.expectCause(isA(EncryptionException.class));

        // WHEN
        FeignFieldLevelEncryptionEncoder instanceUnderTest = new FeignFieldLevelEncryptionEncoder(config, delegate);
        instanceUnderTest.encode(object, type, request);
    }
}
