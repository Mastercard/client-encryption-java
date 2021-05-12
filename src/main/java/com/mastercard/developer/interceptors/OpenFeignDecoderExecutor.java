package com.mastercard.developer.interceptors;

import com.mastercard.developer.encryption.EncryptionConfig;
import com.mastercard.developer.encryption.EncryptionException;
import feign.Response;
import feign.Util;
import feign.codec.DecodeException;
import feign.codec.Decoder;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;

import static com.mastercard.developer.utils.FeignUtils.updateHeader;

/**
 * A Feign decoder for decrypting parts of HTTP payloads.
 */
public abstract class OpenFeignDecoderExecutor implements Decoder {

    public static OpenFeignDecoderExecutor from(EncryptionConfig config, Decoder delegate) {
        return config.getScheme().equals(EncryptionConfig.Scheme.JWE) ?
                new OpenFeignJweDecoder(config, delegate) : new OpenFeignFieldLevelEncryptionDecoder(config, delegate);
    }

    private final Decoder delegate;

    OpenFeignDecoderExecutor(Decoder delegate) {
        this.delegate = delegate;
    }

    protected abstract String decryptPayload(Response response, String responsePayload) throws EncryptionException;

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

            // Decrypt fields & update headers
            String decryptedPayload = decryptPayload(response, responsePayload);
            response = removeHeaders(response);

            response = updateHeader(response, "Content-Length", String.valueOf(decryptedPayload.length()));
            response = response.toBuilder()
                    .body(decryptedPayload, StandardCharsets.UTF_8)
                    .build();
        } catch (EncryptionException e) {
            throw new DecodeException("Failed to intercept and decrypt response!", e);
        }

        // Call the regular decoder
        return this.delegate.decode(response, type);
    }

    protected Response removeHeaders(Response response) {
        return response;
    }
}
