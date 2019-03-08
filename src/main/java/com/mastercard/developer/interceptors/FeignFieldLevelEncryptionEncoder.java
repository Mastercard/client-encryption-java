package com.mastercard.developer.interceptors;

import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.FieldLevelEncryption;
import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;
import feign.RequestTemplate;
import feign.codec.EncodeException;
import feign.codec.Encoder;

import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;

/**
 * A Feign encoder for encrypting parts of HTTP payloads.
 */
public class FeignFieldLevelEncryptionEncoder implements Encoder {

    private final FieldLevelEncryptionConfig config;
    private final Encoder delegate;

    public FeignFieldLevelEncryptionEncoder(FieldLevelEncryptionConfig config, Encoder delegate) {
        this.config = config;
        this.delegate = delegate;
    }

    @Override
    public void encode(Object object, Type type, RequestTemplate requestTemplate) {
        // Call the regular encoder
        delegate.encode(object, type, requestTemplate);

        try {
            // Check request actually has a payload
            byte[] bodyBytes = requestTemplate.body();
            if (null == bodyBytes || bodyBytes.length <= 0) {
                // Nothing to encrypt
                return ;
            }

            // Read request payload
            String payload = new String(bodyBytes, StandardCharsets.UTF_8);

            // Encrypt fields
            String encryptedPayload = FieldLevelEncryption.encryptPayload(payload, config);
            requestTemplate.body(encryptedPayload);
            requestTemplate.header("Content-Length", String.valueOf(encryptedPayload.length()));
        } catch (EncryptionException e) {
            throw new EncodeException("Failed to encrypt request!", e);
        }
    }
}
