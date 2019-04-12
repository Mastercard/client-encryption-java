package com.mastercard.developer.utils;

import com.mastercard.developer.encryption.FieldLevelEncryptionConfig;

import java.io.ByteArrayOutputStream;

public class EncodingUtils {

    private EncodingUtils() {
    }

    public static String encodeBytes(byte[] bytes, FieldLevelEncryptionConfig.FieldValueEncoding encoding) {
        return encoding == FieldLevelEncryptionConfig.FieldValueEncoding.HEX ? hexEncode(bytes) : base64Encode(bytes);
    }

    public static byte[] decodeValue(String value, FieldLevelEncryptionConfig.FieldValueEncoding encoding) {
        return encoding == FieldLevelEncryptionConfig.FieldValueEncoding.HEX ? hexDecode(value) : base64Decode(value);
    }

    protected static String hexEncode(byte[] bytes) {
        if (null == bytes) {
            throw new IllegalArgumentException("Can't hex encode a null value!");
        }
        StringBuilder stringBuilder = new StringBuilder(bytes.length * 2);
        for (byte b: bytes) {
            stringBuilder.append(String.format("%02x", b));
        }
        return stringBuilder.toString();
    }

    protected static byte[] hexDecode(String value) {
        if (null == value) {
            throw new IllegalArgumentException("Can't hex decode a null value!");
        }
        if ("".equals(value)) {
            return new byte[0];
        }
        if (!value.matches("\\p{XDigit}+")) {
            throw new IllegalArgumentException("The provided value is not an hex string!");
        }
        int length = value.length();
        byte[] bytes = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(value.charAt(i),16) << 4) + Character.digit(value.charAt(i + 1),16));
        }
        return bytes;
    }

    private static final char[] b64chars = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
            'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
            'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

    public static String base64Encode(byte[] bytes) {
        if (null == bytes) {
            throw new IllegalArgumentException("Can't base64 encode a null value!");
        }
        StringBuilder buffer = new StringBuilder();
        int pad = 0;
        for (int i = 0; i < bytes.length; i += 3) {
            int b = ((bytes[i] & 0xFF) << 16) & 0xFFFFFF;
            if (i + 1 < bytes.length) {
                b |= (bytes[i + 1] & 0xFF) << 8;
            } else {
                pad++;
            }
            if (i + 2 < bytes.length) {
                b |= (bytes[i + 2] & 0xFF);
            } else {
                pad++;
            }

            for (int j = 0; j < 4 - pad; j++) {
                int c = (b & 0xFC0000) >> 18;
                buffer.append(b64chars[c]);
                b <<= 6;
            }
        }
        for (int j = 0; j < pad; j++) {
            buffer.append("=");
        }
        return buffer.toString();
    }

    private static final int[] b64ints = {
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54,
            55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2,
            3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
            20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30,
            31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
            48, 49, 50, 51, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 };
    
    @SuppressWarnings({"squid:S3776", "squid:ForLoopCounterChangedCheck"})
    public static byte[] base64Decode(String value) {
        if (null == value) {
            throw new IllegalArgumentException("Can't base64 decode a null value!");
        }
        byte[] valueBytes = value.getBytes();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (int i = 0; i < valueBytes.length;) {
            int b;
            if (b64ints[valueBytes[i]] != -1) {
                b = (b64ints[valueBytes[i]] & 0xFF) << 18;
            }
            // skip unknown characters
            else {
                i++;
                continue;
            }

            int num = 0;
            if (i + 1 < valueBytes.length && b64ints[valueBytes[i + 1]] != -1) {
                b = b | ((b64ints[valueBytes[i + 1]] & 0xFF) << 12);
                num++;
            }
            if (i + 2 < valueBytes.length && b64ints[valueBytes[i + 2]] != -1) {
                b = b | ((b64ints[valueBytes[i + 2]] & 0xFF) << 6);
                num++;
            }
            if (i + 3 < valueBytes.length && b64ints[valueBytes[i + 3]] != -1) {
                b = b | (b64ints[valueBytes[i + 3]] & 0xFF);
                num++;
            }

            while (num > 0) {
                int c = (b & 0xFF0000) >> 16;
                outputStream.write((char)c);
                b <<= 8;
                num--;
            }
            i += 4;
        }
        return outputStream.toByteArray();
    }
}
