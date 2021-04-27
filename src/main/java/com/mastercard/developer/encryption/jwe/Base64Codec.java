package com.mastercard.developer.encryption.jwe;

import java.util.Arrays;

class Base64Codec {

    static int computeEncodedLength(final int inputLength) {

        if (inputLength == 0) {
            return 0;
        }

        // Compute the number of complete quads (4-char blocks)
        int fullQuadLength = (inputLength / 3) << 2;

        // Compute the remaining bytes at the end
        int remainder = inputLength % 3;

        // Compute the total
        return remainder == 0 ? fullQuadLength : fullQuadLength + remainder + 1;
    }

    private static int tpSelect(int bool, int whenTrue, int whenFalse) {

        // Will be 0x00000000 when bool == 1, or 0xFFFFFFFF when bool == 0
        final int mask = bool - 1;

        return whenTrue ^ (mask & (whenTrue ^ whenFalse));
    }

    private static int tpLT(int a, int b) {

        return (int) (((long) a - (long) b) >>> 63);
    }

    private static int tpGT(int a, int b) {

        return (int) (((long) b - (long) a) >>> 63);
    }

    private static int tpEq(int a, int b) {

        // This is magic but it will make sense
        // if you think about it for 30 minutes

        final int bit_diff = a ^ b;
        final int msb_iff_zero_diff = (bit_diff - 1) & (~bit_diff);
        return msb_iff_zero_diff >>> 63;
    }

    private static byte encodeDigitBase64URL(int digitIdx) {

        assert digitIdx >= 0 && digitIdx <= 63;

        // Figure out which type of digit this should be
        final int is_uppercase = tpLT(digitIdx, 26);
        final int is_lowercase = tpGT(digitIdx, 25) & tpLT(digitIdx, 52);
        final int is_decimal   = tpGT(digitIdx, 51) & tpLT(digitIdx, 62);
        final int is_62        = tpEq(digitIdx, 62);
        final int is_63        = tpEq(digitIdx, 63);

        // Translate from digit index to ASCII for each hypothetical scenario
        final int as_uppercase = digitIdx + 65;
        final int as_lowercase = digitIdx - 26 + 97;
        final int as_decimal   = digitIdx - 52 + 48;
        final int as_62        = (int) '-';
        final int as_63        = (int) '_';

        // Zero out all scenarios except for the right one, and combine
        final int ascii =
                tpSelect(is_uppercase, as_uppercase, 0) |
                        tpSelect(is_lowercase, as_lowercase, 0) |
                        tpSelect(is_decimal  , as_decimal  , 0) |
                        tpSelect(is_62       , as_62       , 0) |
                        tpSelect(is_63       , as_63       , 0);

        return (byte) ascii;
    }

    private static int decodeDigit(byte ascii) {

        // Figure out which type of digit this is
        final int is_uppercase = tpGT(ascii, 64) & tpLT(ascii, 91);
        final int is_lowercase = tpGT(ascii, 96) & tpLT(ascii, 123);
        final int is_decimal   = tpGT(ascii, 47) & tpLT(ascii, 58);
        final int is_62        = tpEq(ascii, (int) '-') | tpEq(ascii, (int) '+');
        final int is_63        = tpEq(ascii, (int) '_') | tpEq(ascii, (int) '/');

        // It should be one of the five categories
        final int is_valid = is_uppercase | is_lowercase | is_decimal | is_62 | is_63;

        // Translate from ASCII to digit index for each hypothetical scenario
        final int from_uppercase = ascii - 65;
        final int from_lowercase = ascii - 97 + 26;
        final int from_decimal   = ascii - 48 + 52;
        final int from_62        = 62;
        final int from_63        = 63;

        // Zero out all scenarios except for the right one, and combine
        final int digit_idx =
                tpSelect(is_uppercase, from_uppercase, 0) |
                        tpSelect(is_lowercase, from_lowercase, 0) |
                        tpSelect(is_decimal  , from_decimal  , 0) |
                        tpSelect(is_62       , from_62       , 0) |
                        tpSelect(is_63       , from_63       , 0) |
                        tpSelect(is_valid    , 0             , -1);

        assert digit_idx >= -1 && digit_idx <= 63;

        return digit_idx;
    }

    static String encodeToString(byte[] byteArray) {

        // Check special case
        final int sLen = byteArray != null ? byteArray.length : 0;

        if (sLen == 0) {
            return "";
        }

        final int eLen = (sLen / 3) * 3;                      // Length of even 24-bits.
        final int dLen = computeEncodedLength(sLen); // Returned byte count
        final byte[] out = new byte[dLen];

        // Encode even 24-bits
        for (int s = 0, d = 0; s < eLen; ) {

            // Copy next three bytes into lower 24 bits of int, paying attention to sign
            final int i = (byteArray[s++] & 0xff) << 16 | (byteArray[s++] & 0xff) << 8 | (byteArray[s++] & 0xff);

            // Encode the int into four chars
            out[d++] = encodeDigitBase64URL((i >>> 18) & 0x3f);
            out[d++] = encodeDigitBase64URL((i >>> 12) & 0x3f);
            out[d++] = encodeDigitBase64URL((i >>> 6) & 0x3f);
            out[d++] = encodeDigitBase64URL(i & 0x3f);
        }

        // Pad and encode last bits if source isn't even 24 bits
        // according to URL-safe switch
        final int left = sLen - eLen; // 0 - 2.
        if (left > 0) {
            // Prepare the int
            final int i = ((byteArray[eLen] & 0xff) << 10) | (left == 2 ? ((byteArray[sLen - 1] & 0xff) << 2) : 0);

            if (left == 2) {
                out[dLen - 3] = encodeDigitBase64URL(i >> 12);
                out[dLen - 2] = encodeDigitBase64URL((i >>> 6) & 0x3f);
                out[dLen - 1] = encodeDigitBase64URL(i & 0x3f);
            } else {
                out[dLen - 2] = encodeDigitBase64URL(i >> 12);
                out[dLen - 1] = encodeDigitBase64URL((i >>> 6) & 0x3f);
            }
        }

        return new String(out);
    }

    static byte[] decode(final String b64String) {

        // Check special case
        if (b64String == null || b64String.isEmpty()) {
            return new byte[0];
        }

        final byte[] srcBytes = b64String.getBytes();
        final int sLen = srcBytes.length;

        // Calculate output length assuming zero bytes are padding or separators
        final int maxOutputLen = sLen * 6 >> 3;

        // Allocate output array (may be too large)
        final byte[] dstBytes = new byte[maxOutputLen];

        // Process all input bytes
        int d = 0;
        for (int s = 0; s < srcBytes.length; ) {
            // Assemble three bytes into an int from four base 64
            // characters
            int i = 0;

            int j = 0;
            while (j < 4 && s < sLen) {
                // j only increased if a valid char was found
                final int c = decodeDigit(srcBytes[s++]);
                if (c >= 0) {
                    i |= c << (18 - j * 6);
                    j++;
                }
            }

            // j is now the number of valid digits decoded

            // Add output bytes
            if (j >= 2) {
                dstBytes[d++] = (byte) (i >> 16);
                if (j >= 3) {
                    dstBytes[d++] = (byte) (i >> 8);
                    if (j >= 4) {
                        dstBytes[d++] = (byte) i;
                    }
                }
            }
        }

        // d is now the number of output bytes written

        // Copy dstBytes to new array of proper size
        return Arrays.copyOf(dstBytes, d);
    }
}
