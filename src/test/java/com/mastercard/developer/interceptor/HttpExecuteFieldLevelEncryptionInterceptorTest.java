package com.mastercard.developer.interceptor;

import com.google.api.client.http.*;
import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;
import com.mastercard.developer.interceptors.HttpExecuteFieldLevelEncryptionInterceptor;
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

import static com.mastercard.developer.test.TestUtils.getTestFieldLevelEncryptionConfigBuilder;
import static org.hamcrest.core.Is.isA;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class HttpExecuteFieldLevelEncryptionInterceptorTest {

    private static final String JSON_TYPE = "application/json; charset=utf-8";

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void testIntercept_ShouldEncryptRequestPayload() throws Exception {

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
        Assert.assertEquals(868, httpHeaders.getContentLength().intValue());
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
        expectedException.expectMessage("Failed to encrypt request!");
        expectedException.expectCause(isA(EncryptionException.class));

        // WHEN
        HttpExecuteFieldLevelEncryptionInterceptor instanceUnderTest = new HttpExecuteFieldLevelEncryptionInterceptor(config);
        instanceUnderTest.intercept(request);
    }

    @Test
    public void testInterceptResponse_ShouldDecryptResponsePayload() throws Exception {

        // GIVEN
        String encryptedPayload = "{" +
                "    \"encryptedData\": {" +
                "        \"iv\": \"a2c494ca28dec4f3d6ce7d68b1044cfe\"," +
                "        \"encryptedKey\": \"038c65f154a2b07f6c788aaddc13ecead05fdeb11eca0bf576cab7185df66349d2cba4ba51a5304d45995e915bb1de462f0f66acd05026b21340b567d141653a2175ccfe2030b3b49261c6750381421cf0e29bd67840bcdc8092a44691c6c74dcdf620d5a744832fce3b45b8e3f8ad1af6c919195eb7f878c7435143e328e8b858dd232dbfacf7bb2f73981a80a09dc7c6dcd49ad95df527d415438958700b48994d7f6207f03d974a5cf50181205ac0a301a91e94b35ad162c8cf39475d2505d8ae7b1d4ed6f170091ab523f037a75eddb5ca46db9328c10395b69f8b798c280fa0e76f8385a64fe37b67e8578f3f9572dfb87d71e80a97323753030966901b\"," +
                "        \"encryptedValue\": \"0672589113046bf692265b6ea6088184\"," +
                "        \"oaepHashingAlgorithm\": \"SHA256\"" +
                "    }" +
                "}";
        FieldLevelEncryptionConfig config = getTestFieldLevelEncryptionConfigBuilder()
                .withDecryptionPath("$.encryptedData", "$.data")
                .build();
        HttpResponse response = mock(HttpResponse.class);
        HttpHeaders httpHeaders = new HttpHeaders();
        when(response.parseAsString()).thenReturn(encryptedPayload);
        when(response.getHeaders()).thenReturn(httpHeaders);

        // WHEN
        HttpExecuteFieldLevelEncryptionInterceptor instanceUnderTest = new HttpExecuteFieldLevelEncryptionInterceptor(config);
        instanceUnderTest.interceptResponse(response);

        // THEN
        String expectedPayload = "{\"data\":\"string\"}";
        Field contentField = response.getClass().getDeclaredField("content");
        contentField.setAccessible(true);
        InputStream payloadInputStream = (InputStream) contentField.get(response);
        Assert.assertEquals(expectedPayload, IOUtils.toString(payloadInputStream, StandardCharsets.UTF_8));
        Assert.assertEquals(expectedPayload.length(), httpHeaders.getContentLength().intValue());
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
        expectedException.expectMessage("Failed to decrypt response!");
        expectedException.expectCause(isA(EncryptionException.class));

        // WHEN
        HttpExecuteFieldLevelEncryptionInterceptor instanceUnderTest = new HttpExecuteFieldLevelEncryptionInterceptor(config);
        instanceUnderTest.interceptResponse(response);
    }
}
