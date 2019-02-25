package com.mastercard.developer.interceptors;

import com.google.api.client.http.*;
import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.FieldLevelEncryption;
import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

/**
 * A Google Client API interceptor for encrypting/decrypting parts of HTTP payloads.
 * See also:
 * - {@link com.google.api.client.http.HttpExecuteInterceptor}
 * - {@link com.google.api.client.http.HttpResponseInterceptor}
 */
public class HttpExecuteFieldLevelEncryptionInterceptor implements HttpExecuteInterceptor, HttpResponseInterceptor {

    private final FieldLevelEncryptionConfig config;

    public HttpExecuteFieldLevelEncryptionInterceptor(FieldLevelEncryptionConfig config) {
        this.config = config;
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

            // Encrypt fields
            String encryptedPayload = FieldLevelEncryption.encryptPayload(requestPayload, config);
            HttpContent encryptedContent = new ByteArrayContent("application/json; charset=" + StandardCharsets.UTF_8.name(), encryptedPayload.getBytes());
            request.getHeaders().setContentLength(encryptedContent.getLength());
            request.setContent(encryptedContent);

        } catch (EncryptionException e) {
            throw new IOException("Failed to encrypt request!", e);
        }
    }

    @Override
    public void interceptResponse(HttpResponse response) throws IOException {
        try {
            // Read response payload
            String responsePayload = response.parseAsString();
            if (null == responsePayload || responsePayload.length() == 0) {
                // Nothing to encrypt
                return;
            }

            // Decrypt fields
            String decryptedPayload = FieldLevelEncryption.decryptPayload(responsePayload, config);
            HttpContent decryptedContent = new ByteArrayContent("application/json; charset=" + StandardCharsets.UTF_8.name(), decryptedPayload.getBytes());
            response.getHeaders().setContentLength(decryptedContent.getLength());

            // The HttpResponse public interface prevent from updating the response payload:
            // "Do not read from the content stream unless you intend to throw an exception"
            Field contentField = response.getClass().getDeclaredField("content");
            contentField.setAccessible(true);
            contentField.set(response, ((ByteArrayContent) decryptedContent).getInputStream());

        } catch (EncryptionException e) {
            throw new IOException("Failed to decrypt response!", e);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new IOException("Failed to update response with decrypted payload!", e);
        }
    }
}
