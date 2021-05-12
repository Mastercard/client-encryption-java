package com.mastercard.developer.interceptors;

import com.mastercard.developer.encryption.EncryptionConfig;
import com.mastercard.developer.encryption.JweConfig;
import feign.RequestTemplate;
import feign.codec.Encoder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;

import java.lang.reflect.Type;

import static com.mastercard.developer.test.TestUtils.getTestJweConfigBuilder;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.*;

public class OpenFeignJweEncoderTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testFrom_ShouldReturnTheCorrectInterceptor() throws Exception {
        // GIVEN
        EncryptionConfig config = getTestJweConfigBuilder()
                .withEncryptionPath("$.foo", "$.encryptedFoo")
                .build();
        Encoder delegate = mock(Encoder.class);

        OpenFeignEncoderExecutor executor = OpenFeignEncoderExecutor.from(config, delegate);
        assertTrue(executor instanceof OpenFeignJweEncoder);
    }

    @Test
    public void testEncode_ShouldEncryptRequestPayloadAndUpdateContentLengthHeader() throws Exception {

        // GIVEN
        JweConfig config = getTestJweConfigBuilder()
                .withEncryptionPath("$.foo", "$.encryptedFoo")
                .build();

        Type type = mock(Type.class);
        Encoder delegate = mock(Encoder.class);
        Object object = mock(Object.class);
        RequestTemplate request = mock(RequestTemplate.class);
        when(request.body()).thenReturn("{\"foo\":\"bar\"}".getBytes());

        // WHEN
        OpenFeignJweEncoder instanceUnderTest = new OpenFeignJweEncoder(config, delegate);
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
        JweConfig config = getTestJweConfigBuilder()
                .withEncryptionPath("$.foo", "$.encryptedFoo")
                .build();
        Type type = mock(Type.class);
        Encoder delegate = mock(Encoder.class);
        Object object = mock(Object.class);
        RequestTemplate request = mock(RequestTemplate.class);
        when(request.body()).thenReturn(null);

        // WHEN
        OpenFeignJweEncoder instanceUnderTest = new OpenFeignJweEncoder(config, delegate);
        instanceUnderTest.encode(object, type, request);

        // THEN
        verify(request).body();
        verifyNoMoreInteractions(request);
    }

    @Test
    public void testEncode_ShouldDoNothing_WhenEmptyPayload() throws Exception {

        // GIVEN
        JweConfig config = getTestJweConfigBuilder()
                .withEncryptionPath("$.foo", "$.encryptedFoo")
                .build();
        Type type = mock(Type.class);
        Encoder delegate = mock(Encoder.class);
        Object object = mock(Object.class);
        RequestTemplate request = mock(RequestTemplate.class);
        when(request.body()).thenReturn("".getBytes());

        // WHEN
        OpenFeignJweEncoder instanceUnderTest = new OpenFeignJweEncoder(config, delegate);
        instanceUnderTest.encode(object, type, request);

        // THEN
        verify(request).body();
        verifyNoMoreInteractions(request);
    }
}
