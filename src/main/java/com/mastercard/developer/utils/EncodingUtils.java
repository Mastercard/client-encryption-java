package com.mastercard.developer.utils;

import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

public class EncodingUtils {

    private EncodingUtils() {
    }

    public static String encodeBytes(byte[] bytes, FieldLevelEncryptionConfig.FieldValueEncoding encoding) {
        return encoding == FieldLevelEncryptionConfig.FieldValueEncoding.HEX ? new String(Hex.encodeHex(bytes)) : Base64.encodeBase64String(bytes);
    }

    public static byte[] decodeValue(String value, FieldLevelEncryptionConfig.FieldValueEncoding encoding) throws DecoderException {
        return encoding == FieldLevelEncryptionConfig.FieldValueEncoding.HEX ? Hex.decodeHex(value.toCharArray()) : Base64.decodeBase64(value);
    }
}
