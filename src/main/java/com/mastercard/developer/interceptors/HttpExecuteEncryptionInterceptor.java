package com.mastercard.developer.interceptors;

import com.google.api.client.http.ByteArrayContent;
import com.google.api.client.http.HttpContent;
import com.google.api.client.http.HttpExecuteInterceptor;
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpResponseInterceptor;
import com.mastercard.developer.encryption.EncryptionConfig;
import com.mastercard.developer.encryption.EncryptionException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

import static com.mastercard.developer.utils.StringUtils.isNullOrEmpty;

/**
 * A Google Client API interceptor for encrypting/decrypting parts of HTTP payloads.
 * See also:
 * - {@link com.google.api.client.http.HttpExecuteInterceptor}
 * - {@link com.google.api.client.http.HttpResponseInterceptor}
 */
public abstract class HttpExecuteEncryptionInterceptor implements HttpExecuteInterceptor, HttpResponseInterceptor {

    protected abstract String encryptPayload(HttpHeaders headers, String requestPayload) throws EncryptionException;

    protected abstract String decryptPayload(HttpHeaders headers, String responsePayload) throws EncryptionException;

    public static HttpExecuteEncryptionInterceptor from(EncryptionConfig config) {
        return config.getScheme().equals(EncryptionConfig.Scheme.JWE) ? new HttpExecuteJweInterceptor(config) : new HttpExecuteFieldLevelEncryptionInterceptor(config) {
        };
    }

    @Override
    public void intercept(HttpRequest request) throws IOException {
        try {
            // Check request actually has a payload
            HttpContent content = request.getContent();
            if (null == content || content.getLength() == 0) {
                // Nothing to encrypt
                return;
            }

            // Read request payload
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            content.writeTo(outputStream);
            String requestPayload = outputStream.toString(StandardCharsets.UTF_8.name());

            // Encrypt fields & update headers
            HttpHeaders headers = request.getHeaders();
            String encryptedPayload = encryptPayload(headers, requestPayload);

            HttpContent encryptedContent = new ByteArrayContent("application/json; charset=" + StandardCharsets.UTF_8.name(), encryptedPayload.getBytes());
            headers.setContentLength(encryptedContent.getLength());
            request.setContent(encryptedContent);

        } catch (EncryptionException e) {
            throw new IOException("Failed to intercept and encrypt request!", e);
        }
    }

    @Override
    @java.lang.SuppressWarnings("squid:S3011")
    public void interceptResponse(HttpResponse response) throws IOException {
        try {
            // Read response payload
            String responsePayload = response.parseAsString();
            if (isNullOrEmpty(responsePayload)) {
                // Nothing to encrypt
                return;
            }

            // Decrypt fields & update headers
            HttpHeaders headers = response.getHeaders();
            String decryptedPayload = decryptPayload(headers, responsePayload);

            ByteArrayContent decryptedContent = new ByteArrayContent("application/json; charset=" + StandardCharsets.UTF_8.name(), decryptedPayload.getBytes());
            headers.setContentLength(decryptedContent.getLength());

            // The HttpResponse public interface prevent from updating the response payload:
            // "Do not read from the content stream unless you intend to throw an exception"
            Field contentField = response.getClass().getDeclaredField("content");
            contentField.setAccessible(true);
            contentField.set(response, decryptedContent.getInputStream());

        } catch (EncryptionException e) {
            throw new IOException("Failed to intercept and decrypt response!", e);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new IOException("Failed to update response with decrypted payload!", e);
        }
    }

    static void removeHeader(HttpHeaders headers, String name) {
        if (name == null) {
            // Do nothing
            return;
        }
        headers.remove(name);
    }

    static void updateHeader(HttpHeaders headers, String name, String value) {
        if (name == null) {
            // Do nothing
            return;
        }
        headers.remove(name);
        headers.set(name, value);
    }
}
