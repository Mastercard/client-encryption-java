package com.mastercard.developer.interceptors;

import com.mastercard.developer.encryption.EncryptionException;
import com.mastercard.developer.encryption.FieldLevelEncryption;
import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;
import com.mastercard.developer.encryption.FieldLevelEncryptionParams;
import feign.Response;
import feign.Util;
import feign.codec.DecodeException;
import feign.codec.Decoder;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;

import static com.mastercard.developer.utils.FeignUtils.*;

/**
 * A Feign decoder for decrypting parts of HTTP payloads.
 */
public class OpenFeignFieldLevelEncryptionDecoder implements Decoder {

    private final FieldLevelEncryptionConfig config;
    private final Decoder delegate;

    public OpenFeignFieldLevelEncryptionDecoder(FieldLevelEncryptionConfig config, Decoder delegate) {
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

            // Decrypt fields & update headers
            String decryptedPayload;
            if (config.useHttpHeaders()) {
                // Read encryption params from HTTP headers and delete headers
                String ivValue = readHeader(response, config.getIvHeaderName());
                response = removeHeader(response, config.getIvHeaderName());
                String oaepPaddingDigestAlgorithmValue = readHeader(response, config.getOaepPaddingDigestAlgorithmHeaderName());
                response = removeHeader(response, config.getOaepPaddingDigestAlgorithmHeaderName());
                String encryptedKeyValue = readHeader(response, config.getEncryptedKeyHeaderName());
                response = removeHeader(response, config.getEncryptedKeyHeaderName());
                response = removeHeader(response, config.getEncryptionCertificateFingerprintHeaderName());
                response = removeHeader(response, config.getEncryptionKeyFingerprintHeaderName());
                FieldLevelEncryptionParams params = new FieldLevelEncryptionParams(ivValue, encryptedKeyValue, oaepPaddingDigestAlgorithmValue, config);
                decryptedPayload = FieldLevelEncryption.decryptPayload(responsePayload, config, params);
            } else {
                // Encryption params are stored in the payload
                decryptedPayload = FieldLevelEncryption.decryptPayload(responsePayload, config);
            }
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
}
