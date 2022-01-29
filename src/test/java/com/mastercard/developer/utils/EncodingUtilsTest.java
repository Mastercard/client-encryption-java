package com.mastercard.developer.utils;

import org.junit.Assert;
import org.junit.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class EncodingUtilsTest {

    @Test
    public void testHexEncode() {
        Assert.assertEquals("00", EncodingUtils.hexEncode(new byte[1]));
        Assert.assertEquals("736f6d652064617461", EncodingUtils.hexEncode("some data".getBytes()));
        Assert.assertEquals("", EncodingUtils.hexEncode("".getBytes()));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHexEncode_ShouldThrowIllegalArgumentException_WhenNullValue() {
        EncodingUtils.hexEncode(null);
    }

    @Test
    public void testHexEncode_ShouldKeepLeadingZeros() throws NoSuchAlgorithmException {
        String hex = EncodingUtils.hexEncode(MessageDigest.getInstance("SHA-256").digest("WIDDIES".getBytes()));
        Assert.assertEquals("000000c71f1bda5b63f5165243e10394bc9ebf62e394ef7c6e049c920ea1b181", hex);
    }

    @Test
    public void testHexDecode() {
        Assert.assertArrayEquals(new byte[1], EncodingUtils.hexDecode("00"));
        Assert.assertArrayEquals("some data".getBytes(), EncodingUtils.hexDecode("736f6d652064617461"));
        Assert.assertArrayEquals("some data".getBytes(), EncodingUtils.hexDecode("736F6D652064617461"));
        Assert.assertArrayEquals("".getBytes(), EncodingUtils.hexDecode(""));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHexDecode_ShouldThrowIllegalArgumentException_WhenNotAnHexValue() {
        EncodingUtils.hexDecode("not an hex string!");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testHexDecode_ShouldThrowIllegalArgumentException_WhenNullValue() {
        EncodingUtils.hexDecode(null);
    }

    @Test
    public void testBase64Encode() {
        Assert.assertEquals("AA==", EncodingUtils.base64Encode(new byte[1]));
        Assert.assertEquals("c29tZSBkYXRh", EncodingUtils.base64Encode("some data".getBytes()));
        Assert.assertEquals("", EncodingUtils.base64Encode("".getBytes()));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testBase64Encode_ShouldThrowIllegalArgumentException_WhenNullValue() {
        EncodingUtils.base64Encode(null);
    }

    @Test
    public void testBase64Decode() {
        Assert.assertArrayEquals(new byte[1], EncodingUtils.base64Decode("AA=="));
        Assert.assertArrayEquals("some data".getBytes(), EncodingUtils.base64Decode("c29tZSBkYXRh"));
        Assert.assertArrayEquals("".getBytes(), EncodingUtils.base64Decode(""));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testBase64Decode_ShouldThrowIllegalArgumentException_WhenNullValue() {
        EncodingUtils.base64Decode(null);
    }

    @Test
    public void testBase64UrlEncode() {
        Assert.assertEquals("AA", EncodingUtils.base64UrlEncode(new byte[1]));
        Assert.assertEquals("eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ", EncodingUtils.base64UrlEncode("{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}".getBytes()));
        Assert.assertEquals("bGlnaHQgd29yaw", EncodingUtils.base64UrlEncode("light work".getBytes()));
    }
}
