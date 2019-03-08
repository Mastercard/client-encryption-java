package com.mastercard.developer.interceptors;

import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.FieldLevelEncryption;
import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;
import feign.Response;
import feign.Util;
import feign.codec.DecodeException;
import feign.codec.Decoder;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * A Feign decoder for decrypting parts of HTTP payloads.
 */
public class FeignFieldLevelEncryptionDecoder implements Decoder {

    private final FieldLevelEncryptionConfig config;
    private final Decoder delegate;

    public FeignFieldLevelEncryptionDecoder(FieldLevelEncryptionConfig config, Decoder delegate) {
        this.config = config;
        this.delegate = delegate;
    }

    @Override
    public Object decode(Response response, Type type) throws IOException {
        try {
            // Check response actually has a payload
            Response.Body body = response.body();
            if (body == null || body.length() <= 0) {
                // Nothing to decrypt
                return this.delegate.decode(response, type);
            }

            // Read response payload
            String responsePayload = Util.toString(body.asReader());

            // Decrypt fields
            String decryptedPayload = FieldLevelEncryption.decryptPayload(responsePayload, config);
            Map<String, Collection<String>> headers = new HashMap<>(response.headers());
            updateContentLength(headers, String.valueOf(decryptedPayload.length()));
            response = response.toBuilder()
                    .body(decryptedPayload, StandardCharsets.UTF_8)
                    .headers(headers)
                    .build();
        } catch (EncryptionException e) {
            throw new DecodeException("Failed to decrypt response!", e);
        }

        // Call the regular decoder
        return this.delegate.decode(response, type);
    }

    private static void updateContentLength(Map<String, Collection<String>> headers, String length) {
        Set<String> headerNames = new HashSet<>(headers.keySet());
        for (String headerName : headerNames) {
            if (headerName.equalsIgnoreCase("content-length")) {
                headers.remove(headerName);
            }
        }
        headers.put("Content-Length", Collections.singleton(length));
    }
}
