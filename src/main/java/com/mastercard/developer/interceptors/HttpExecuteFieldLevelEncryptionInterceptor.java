package com.mastercard.developer.interceptors;

import com.google.api.client.http.*;
import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.FieldLevelEncryption;
import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;
import com.mastercard.developer.encryption.FieldLevelEncryptionParams;

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

            // Encrypt fields & update headers
            String encryptedPayload;
            HttpHeaders headers = request.getHeaders();
            if (config.useHttpHeaders()) {
                // Generate encryption params and add them as HTTP headers
                FieldLevelEncryptionParams params = FieldLevelEncryptionParams.generate(config);
                updateHeader(headers, config.getIvHeaderName(), params.getIvValue());
                updateHeader(headers, config.getEncryptedKeyHeaderName(), params.getEncryptedKeyValue());
                updateHeader(headers, config.getEncryptionCertificateFingerprintHeaderName(), config.getEncryptionCertificateFingerprint());
                updateHeader(headers, config.getEncryptionKeyFingerprintHeaderName(), config.getEncryptionKeyFingerprint());
                updateHeader(headers, config.getOaepPaddingDigestAlgorithmHeaderName(), params.getOaepPaddingDigestAlgorithmValue());
                encryptedPayload = FieldLevelEncryption.encryptPayload(requestPayload, config, params);
            } else {
                // Encryption params will be stored in the payload
                encryptedPayload = FieldLevelEncryption.encryptPayload(requestPayload, config);
            }
            
            HttpContent encryptedContent = new ByteArrayContent("application/json; charset=" + StandardCharsets.UTF_8.name(), encryptedPayload.getBytes());
            headers.setContentLength(encryptedContent.getLength());
            request.setContent(encryptedContent);

        } catch (EncryptionException e) {
            throw new IOException("Failed to intercept and encrypt request!", e);
        }
    }

    @Override
    public void interceptResponse(HttpResponse response) throws IOException {
        try {
            // Read response payload
            String responsePayload = response.parseAsString();
            if (isNullOrEmpty(responsePayload)) {
                // Nothing to encrypt
                return;
            }

            // Decrypt fields & update headers
            String decryptedPayload;
            HttpHeaders headers = response.getHeaders();
            if (config.useHttpHeaders()) {
                // Read encryption params from HTTP headers and delete headers
                String ivValue = headers.getFirstHeaderStringValue(config.getIvHeaderName());
                String oaepPaddingDigestAlgorithmValue = headers.getFirstHeaderStringValue(config.getOaepPaddingDigestAlgorithmHeaderName());
                String encryptedKeyValue = headers.getFirstHeaderStringValue(config.getEncryptedKeyHeaderName());
                removeHeader(headers, config.getIvHeaderName());
                removeHeader(headers, config.getEncryptedKeyHeaderName());
                removeHeader(headers, config.getOaepPaddingDigestAlgorithmHeaderName());
                removeHeader(headers, config.getEncryptionCertificateFingerprintHeaderName());
                removeHeader(headers, config.getEncryptionKeyFingerprintHeaderName());
                FieldLevelEncryptionParams params = new FieldLevelEncryptionParams(ivValue, encryptedKeyValue, oaepPaddingDigestAlgorithmValue, config);
                decryptedPayload = FieldLevelEncryption.decryptPayload(responsePayload, config, params);
            } else {
                // Encryption params are stored in the payload
                decryptedPayload = FieldLevelEncryption.decryptPayload(responsePayload, config);
            }

            HttpContent decryptedContent = new ByteArrayContent("application/json; charset=" + StandardCharsets.UTF_8.name(), decryptedPayload.getBytes());
            headers.setContentLength(decryptedContent.getLength());

            // The HttpResponse public interface prevent from updating the response payload:
            // "Do not read from the content stream unless you intend to throw an exception"
            Field contentField = response.getClass().getDeclaredField("content");
            contentField.setAccessible(true);
            contentField.set(response, ((ByteArrayContent) decryptedContent).getInputStream());

        } catch (EncryptionException e) {
            throw new IOException("Failed to intercept and decrypt response!", e);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new IOException("Failed to update response with decrypted payload!", e);
        }
    }

    private static void removeHeader(HttpHeaders headers, String name) {
        if (name == null) {
            // Do nothing
            return;
        }
        headers.remove(name);
    }

    private static void updateHeader(HttpHeaders headers, String name, String value) {
        if (name == null) {
            // Do nothing
            return;
        }
        headers.remove(name);
        headers.set(name, value);
    }
}
